/*
  Make Way - ESP32 relay node

  What it does
    1. Listens for Make Way alerts (90-byte Bluetooth LE extended advertisements).
    2. Blinks an LED while alerts keep arriving (stops 5 s after the last one).
    3. Repeats each NEW alert with the hop count (TTL) lowered by one.
  No location checks. No filtering by direction or lane.

  HARDWARE: needs a chip with Bluetooth 5 (extended advertising):
    ESP32-S3, ESP32-C3, ESP32-C6 or ESP32-H2.   The original "ESP32" (classic) CANNOT work:
    it only has Bluetooth 4.2 and cannot send or receive 90-byte advertisements.

  SETUP (Arduino IDE)
    1. Boards Manager: install "esp32" by Espressif. Select your board (e.g. "ESP32S3 Dev Module").
    2. Library Manager: install "NimBLE-Arduino" by h2zero (version 2.x).
    3. Open  Documents/Arduino/libraries/NimBLE-Arduino/src/nimconfig.h  and set:
           #define CONFIG_BT_NIMBLE_EXT_ADV 1
       If a line like CONFIG_BT_NIMBLE_EXT_ADV_MAX_SIZE is there, set it to at least 255.
       (PlatformIO users: add  -DCONFIG_BT_NIMBLE_EXT_ADV=1  to build_flags instead.)
    4. Wire an LED: GPIO LED_PIN -> 220 ohm resistor -> LED long leg; LED short leg -> GND.
    5. Upload, open Serial Monitor at 115200.

  OPTIONAL SECURITY: set VERIFY_SIGNATURE to 1 so the node only repeats alerts signed by your
  ambulance (needs the "Crypto" library by Rhys Weatherley). With 0, the node repeats ANY alert
  in the right format, including forged ones, so use 0 only for bench testing.
*/

#include <NimBLEDevice.h>

#if !CONFIG_BT_NIMBLE_EXT_ADV
#error "Enable CONFIG_BT_NIMBLE_EXT_ADV in NimBLE-Arduino's nimconfig.h (see SETUP step 3 above)."
#endif

// ----------------------------- settings -----------------------------
#define LED_PIN          4        // external LED (many S3/C3 boards have only an RGB LED on the board)
#define LED_ACTIVE_HIGH  1        // 1: HIGH turns the LED on, 0: LOW turns it on
#define BLINK_MS         100      // on/off time while alerting
#define ALERT_HOLD_MS    5000     // keep blinking this long after the last alert
#define RELAY_ADV_MS     2500     // how long to repeat each relayed alert
#define VERIFY_SIGNATURE 0        // 1 = only repeat alerts signed by the ambulance

// Public key printed by:  python laptop_ambulance.py --show-key   (64 hex characters)
const char* PUBLIC_KEY_HEX = "d0a0854c0cc2b43bbc59a0b28fc8f507a8e47d3f5945994c5edbd3ac9087750d";

// ----------------------------- packet format (version 2) -----------------------------
// version(1) keyId(4) seq(4) ts(4) lat(4) lon(4) heading(2) speed(1) lane(1) | ttl(1) | sig(64)
static const uint16_t COMPANY_ID     = 0xFFFF;
static const size_t   PACKET_SIZE    = 90;
static const uint8_t  PACKET_VERSION = 2;
static const size_t   SIGNED_SIZE    = 25;
static const size_t   TTL_INDEX      = 25;
static const size_t   SIG_INDEX      = 26;

#if VERIFY_SIGNATURE
#include <Ed25519.h>              // Library "Crypto" by Rhys Weatherley
static uint8_t publicKey[32];
#endif

// ----------------------------- state -----------------------------
static uint32_t lastSeq = 0;
static bool     haveSeq = false;
static uint32_t lastAlertMs = 0;
static bool     everAlerted = false;

static volatile bool     relayPending = false;
static volatile uint32_t relayAtMs = 0;
static uint8_t           relayBuf[PACKET_SIZE];

// ----------------------------- helpers -----------------------------
static void ledWrite(bool on) {
  digitalWrite(LED_PIN, (on == (LED_ACTIVE_HIGH == 1)) ? HIGH : LOW);
}

#if VERIFY_SIGNATURE
static bool parseHex(const char* hex, uint8_t* out, size_t n) {
  if (strlen(hex) != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
    char* end = nullptr;
    long v = strtol(b, &end, 16);
    if (*end != 0) return false;
    out[i] = (uint8_t)v;
  }
  return true;
}
#endif

// Called from the Bluetooth scan callback for every candidate packet.
static void handlePacket(const uint8_t* p, int rssi) {
  if (p[0] != PACKET_VERSION) return;

#if VERIFY_SIGNATURE
  if (!Ed25519::verify(p + SIG_INDEX, publicKey, p, SIGNED_SIZE)) {
    Serial.println("Rejected: bad signature");
    return;
  }
#endif

  uint32_t seq = ((uint32_t)p[5] << 24) | ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 8) | (uint32_t)p[8];
  if (haveSeq && seq <= lastSeq) return;      // already handled (also stops relay loops)
  haveSeq = true;
  lastSeq = seq;

  uint8_t lane = p[24];
  uint8_t ttl  = p[TTL_INDEX];
  Serial.printf("ALERT seq=%lu lane=%u ttl=%u rssi=%d\n", (unsigned long)seq, lane, ttl, rssi);

  lastAlertMs = millis();
  everAlerted = true;

  if (ttl > 0 && !relayPending) {
    memcpy(relayBuf, p, PACKET_SIZE);
    relayBuf[TTL_INDEX] = ttl - 1;            // the signature does not cover TTL, so it stays valid
    relayAtMs = millis() + random(50, 200);   // small random delay avoids collisions between nodes
    relayPending = true;
  }
}

class ScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    std::string m = dev->getManufacturerData();            // 2-byte company id + our 90 bytes
    if (m.size() != PACKET_SIZE + 2) return;
    if ((uint8_t)m[0] != (COMPANY_ID & 0xFF) || (uint8_t)m[1] != (COMPANY_ID >> 8)) return;
    handlePacket((const uint8_t*)m.data() + 2, dev->getRSSI());
  }
  void onScanEnd(const NimBLEScanResults& results, int reason) override {
    NimBLEDevice::getScan()->start(0, false, true);        // keep scanning forever
  }
} scanCallbacks;

// Re-broadcast the stored packet as a Bluetooth 5 extended advertisement.
static void doRelay() {
  static uint8_t buf[PACKET_SIZE + 2];
  buf[0] = COMPANY_ID & 0xFF;
  buf[1] = COMPANY_ID >> 8;
  memcpy(buf + 2, relayBuf, PACKET_SIZE);

  NimBLEExtAdvertisement adv(BLE_HCI_LE_PHY_1M, BLE_HCI_LE_PHY_1M);
  adv.setLegacyAdvertising(false);
  adv.setConnectable(false);
  adv.setScannable(false);
  adv.setManufacturerData(buf, sizeof(buf));

  NimBLEExtAdvertising* a = NimBLEDevice::getAdvertising();
  if (a->isActive(0)) a->stop(0);
  a->setInstanceData(0, adv);
  a->start(0, RELAY_ADV_MS, 0);                            // instance 0, duration in ms, no event limit
  Serial.printf("Relayed (ttl now %u)\n", relayBuf[TTL_INDEX]);
}

// ----------------------------- Arduino -----------------------------
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  ledWrite(false);

#if VERIFY_SIGNATURE
  if (!parseHex(PUBLIC_KEY_HEX, publicKey, 32)) {
    Serial.println("PUBLIC_KEY_HEX is not 64 hex characters. Fix it and re-upload.");
    while (true) { ledWrite(true); delay(100); ledWrite(false); delay(100); }
  }
#endif

  NimBLEDevice::init("MakeWay-node");

  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(&scanCallbacks, false);
  scan->setActiveScan(false);
  scan->setDuplicateFilter(0);                              // we need every new packet, not one per device
  scan->setMaxResults(0);
  scan->setInterval(100);
  scan->setWindow(100);
  scan->setPhy(NimBLEScan::Phy::PHY_1M);                    // phones and the laptop advertise on 1M
  scan->start(0, false, true);

  Serial.println("Make Way node ready: listening, relaying, LED on alert");
}

void loop() {
  // send the pending relay once its small random delay has passed
  if (relayPending && (int32_t)(millis() - relayAtMs) >= 0) {
    doRelay();
    relayPending = false;
  }

  // blink while alerts keep arriving
  bool alerting = everAlerted && (millis() - lastAlertMs) < ALERT_HOLD_MS;
  if (alerting) ledWrite(((millis() / BLINK_MS) % 2) == 0);
  else          ledWrite(false);

  delay(5);
}
