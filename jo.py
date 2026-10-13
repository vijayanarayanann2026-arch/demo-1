/*
  Secure RFID Access Control  -  Arduino Uno + MFRC522 + SG90 servo

  TWO STAGES (change SECURITY_STAGE below):

  STAGE 1  XOR demo (teaching only, INSECURE)
           Scanned UID is XOR-ed with a fixed key and compared to a stored value.
           A cloned card has the same UID, so it gets the same XOR result and PASSES.
           Use this to demonstrate test T3 failing.

  STAGE 2  Per-card secret keys (the fix)
           Each card's sector 1 is locked with a key derived from
           HMAC-SHA256(MASTER_SECRET, card UID). The reader derives the same key,
           authenticates, and checks a secret token stored in block 4.
           A clone that only copies the UID has the wrong keys, so authentication fails.

  WIRING (Arduino Uno)
    MFRC522  SDA/SS -> D10    SCK -> D13    MOSI -> D11    MISO -> D12
             RST -> D9        3.3V -> 3.3V (NOT 5V)        GND -> GND
    Servo    signal -> D6     power from a separate 5V supply (or 5V pin + 470uF cap)
             ground MUST be shared with the Arduino
    Green LED -> D4 (via 220 ohm)      Red LED -> D5 (via 220 ohm)

  LIBRARIES (Arduino IDE > Library Manager)
    - MFRC522 by GithubCommunity (miguelbalboa)
    - Crypto by Rhys Weatherley  (only needed for Stage 2)
    - Servo (built in)

  SERIAL MONITOR: 9600 baud, "Newline" line ending.
    Stage 2: type  e  and press Enter, then tap a FACTORY-NEW card to enroll it.

  TEST PLAN
    T1 valid card       -> unlocks (both stages)
    T2 unknown card     -> denied  (both stages)
    T3 UID-only clone   -> Stage 1: UNLOCKS (attack works)   Stage 2: DENIED
    T4 timing           -> compare Serial timestamps
*/

#include <SPI.h>
#include <MFRC522.h>
#include <Servo.h>

#define SECURITY_STAGE 2      // 1 = XOR demo (insecure), 2 = per-card keys

#if SECURITY_STAGE == 2
#include <SHA256.h>
#endif

// ---------------- Pins and settings ----------------
const byte PIN_SS    = 10;
const byte PIN_RST   = 9;
const byte PIN_SERVO = 6;
const byte PIN_GREEN = 4;
const byte PIN_RED   = 5;

const int ANGLE_LOCKED   = 0;
const int ANGLE_UNLOCKED = 90;
const unsigned long UNLOCK_MS  = 3000;   // how long the door stays unlocked
const byte MAX_FAILS = 3;                // lockout after this many bad scans in a row
const unsigned long LOCKOUT_MS = 5000;

MFRC522 mfrc522(PIN_SS, PIN_RST);
Servo lockServo;

byte failCount = 0;
bool enrollMode = false;

// ---------------- Small helpers ----------------
void printHex(const byte *data, byte len) {
  for (byte i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print('0');
    Serial.print(data[i], HEX);
    Serial.print(' ');
  }
  Serial.println();
}

// compares without exiting early (avoids leaking how many bytes matched)
bool safeEqual(const byte *a, const byte *b, byte n) {
  byte diff = 0;
  for (byte i = 0; i < n; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

void grantAccess() {
  Serial.println(F(">>> ACCESS GRANTED"));
  failCount = 0;
  digitalWrite(PIN_GREEN, HIGH);
  lockServo.write(ANGLE_UNLOCKED);
  delay(UNLOCK_MS);
  lockServo.write(ANGLE_LOCKED);
  digitalWrite(PIN_GREEN, LOW);
}

void denyAccess() {
  Serial.println(F(">>> ACCESS DENIED"));
  failCount++;
  for (byte i = 0; i < 3; i++) {
    digitalWrite(PIN_RED, HIGH); delay(150);
    digitalWrite(PIN_RED, LOW);  delay(150);
  }
  if (failCount >= MAX_FAILS) {
    Serial.println(F("Too many failed attempts - locked out briefly"));
    digitalWrite(PIN_RED, HIGH);
    delay(LOCKOUT_MS);
    digitalWrite(PIN_RED, LOW);
    failCount = 0;
  }
}

// =====================================================================
//  STAGE 1: XOR demo (INSECURE - for teaching)
// =====================================================================
#if SECURITY_STAGE == 1

// Put YOUR authorized card's UID here (scan it once; the UID prints in Serial).
const byte AUTH_UID[4] = {0xDE, 0xAD, 0xBE, 0xEF};
const byte XOR_KEY[4]  = {0x5A, 0xC3, 0x17, 0x9E};
byte storedEnc[4];



