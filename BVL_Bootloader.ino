/*
 * Copyright (c) 2018, Black Vault Labs LLC.
 * All rights reserved.
 * 
 * If you need this library for commercial use contact software@blackvaultlabs.com
 *
*/

/************************************************************
* K20 Flash Config
* 
* 262,144 / 2048 = 128 sectors available in P-flash
* 0x0000_0000 - 0x0000_604F used for bootloader up to 24656 bytes
* 0x0000_6050 - Empty  between bootloader and firmware
* 0x0000_6060 - 0x0003_AFEF used for firmware 216976 bytes (13 blocks of 16384 = 212992 bytes max size fw)
* 0x0003_AFF0 - Empty between firmware and data storage
* 0x0003_B000 - 0x0003_FFFF used for data storage 20480 bytes (10 sectors, 8 used, 2 reserved)
* TODO - Adjust wear leveling to use D-flash as data storage instead of P-flash (Tradeoff - Larger fw file support / Lower EEPROM write limit)
************************************************************/

#include "tweetnacl.h"
#include "Adafruit_NeoPixel.h"

//#define DEBUG

#ifdef DEBUG
#define wait 3
#else
#define wait 0
#endif

/************************************************************
* Macros
************************************************************/
#define IS_JUMP_TO_OFFSET_FLAG_SET()  (eeprom_read_byte(0x00) != 1) //If 0 or 255 go to firmware
#define CLEAR_JUMP_FLAG()             eeprom_write_byte(0x00, 1) //Go to bootloader
#define SET_JUMP_FLAG()               eeprom_write_byte(0x00, 0) //Go to firmware
#define IS_FWLOAD_FLAG_SET()  (eeprom_read_byte((unsigned char *)0x01) == 1) //If 1 there is firmware ready to load
#define SET_FWLOAD_FLAG()               eeprom_write_byte((unsigned char *)0x01, 1) //Firmware ready to load
#define CLEAR_FWLOAD_FLAG()             eeprom_write_byte((unsigned char *)0x01, 0) //Firmware not ready to load
#define GET_STORED_HASH(i) eeprom_read_byte((unsigned char*)(2+i));
#define GPIO_CONFIG   (*(volatile unsigned short *)0x40048038)
#define FWSTARTADR    (unsigned long *)0x6060 //SET TO THE JUMP ADDRESS
#define FWENDADR    (unsigned long *)0x3AFEF //SET TO THE LAST USABLE FW ADDRESS
#define SECTORSIZE 2048
#define GET_ADDR(sector, addr) (!((uintptr_t)(addr) & (sector - 1)))
  
/************************************************************
* Global
************************************************************/
bool DONE = false;
unsigned char lastsigpart1[32] = {0}; //last signature part 1
unsigned char lastsigpart2[32] = {0}; //last signature part 2
uint8_t writtenblocks = 0;
uint8_t recv_buffer[64];
//NaCl - http://nacl.cr.yp.to/sign.html
const unsigned char pk[64] = "\x57\x76\x84\x88\xc3\xeb\xe6\x39\x49\x89\xb8\x1d\x7e\xe9\x3b\xda\x86\x7f\x6d\x81\x64\x74\xd5\xaa\x38\xb2\x6c\xd6\x4c\xe6\x7e\x65"; //public key
unsigned long long mlen;
unsigned char smesg[17000];
unsigned int offsetindex = 0;

#ifdef __cplusplus
extern "C" {
#endif

void jumpToApplicationAt0x6060() {
  /* Load stack pointer and program counter from start of new program */
  asm("movw r0, #0x6060");
  asm("ldr sp, [r0]");
  asm("ldr pc, [r0, #4]");
}

// if jumping to an address at 0x10000 or higher, need to load 32-bits into r0
void jumpToApplicationAt0x36060() {
  /* Load stack pointer and program counter from start of new program */
  asm("movw r0, #0x6060");
  asm("movt r0, #0x0003");
  asm("ldr sp, [r0]");
  asm("ldr pc, [r0, #4]");
}

void resetPeripherals() {
  /* set (some of) USB back to normal */
  NVIC_DISABLE_IRQ(IRQ_USBOTG);
  NVIC_CLEAR_PENDING(IRQ_USBOTG);
  SIM_SCGC4 &= ~(SIM_SCGC4_USBOTG);
  /* disable all GPIO interrupts */
  NVIC_DISABLE_IRQ(IRQ_PORTA);
  NVIC_DISABLE_IRQ(IRQ_PORTB);
  NVIC_DISABLE_IRQ(IRQ_PORTC);
  NVIC_DISABLE_IRQ(IRQ_PORTD);
  NVIC_DISABLE_IRQ(IRQ_PORTE);
  /* set (some of) ADC1 back to normal */
  // wait until calibration is complete
  while(ADC1_SC3 & ADC_SC3_CAL);
  // clear flag if calibration failed
  if(ADC1_SC3 & 1<<6)
    ADC1_SC3 |= 1<<6;
  // clear conversion complete flag (which could trigger ISR otherwise)
  if(ADC1_SC1A & 1<<7)
    ADC1_SC1A |= 1<<7;
  /* set some clocks back to default/reset settings */
  MCG_C1 = MCG_C1_CLKS(2) | MCG_C1_FRDIV(4);
  SIM_CLKDIV1 = 0;
  SIM_CLKDIV2 = 0;
}

void flasherase(uint32_t *adr) {
  if (adr>=FWSTARTADR) //Protect Bootloader from being erased
    {
      GET_ADDR(2048,adr);
      while ((FTFL_FSTAT & 128) == 0) {}   // wait for previous commands to complete
      FTFL_FSTAT  = 48;
      FTFL_FCCOB3 = ((uint32_t)adr);
      FTFL_FCCOB2 = ((uint32_t)adr) >> 8;
      FTFL_FCCOB1 = ((uint32_t)adr) >> 16;
      FTFL_FCCOB0 = 9;
      __disable_irq();
      doram(&FTFL_FSTAT);
      __enable_irq();    
    }
}

void eraseflash() {
  uint8_t sectorindex = 0;
  while((unsigned long)FWSTARTADR + ((unsigned long)SECTORSIZE*sectorindex) <= (unsigned long)FWENDADR) {
    uintptr_t adr = (unsigned long)FWSTARTADR + ((unsigned long)SECTORSIZE*sectorindex);
    //Erase flash sectors
    flasherase((unsigned long*)adr);
    sectorindex++;
  }
}

int fwintegritycheck(unsigned char* hashptr) {
   //Firmware Integrity Check
   unsigned long adr = (unsigned long)FWSTARTADR;
   unsigned char temphash[crypto_hash_BYTES];
   int hashsum = 0;
   //Hash current fw in hashptr   
   while (adr <= 0x36060) { //13 blocks of 16384 bytes, last block 0x36060 - 0x3A060
     flashget_common (smesg, (unsigned long*)adr, 16384); //Read each block
     if (adr == (unsigned long)FWSTARTADR) { 
       crypto_hash(hashptr,smesg,16384); //hash this block
     }
     else { //if not first block, hash with previous block hash
     memcpy(smesg + 16384, hashptr, crypto_hash_BYTES);
     crypto_hash(hashptr,smesg,(16384+crypto_hash_BYTES)); 
     }
     adr = adr + 16384;
  }
  //Read stored hash
    for (int i = 0; i < crypto_hash_BYTES; i++) { //read 64byte hash from eeprom
    temphash[i] = GET_STORED_HASH(i); // 0 used for bootloader jump flag, 1 used for fwload flag, 2-65 used for fw integrity hash
    hashsum = hashsum + temphash[i];
    }
    if (hashsum == 16320) { //All FFs, default state, no hash written
      return 1;
    } //Check match
    else if (crypto_verify_32(temphash, hashptr) == 0 && crypto_verify_32(temphash+32, hashptr+32) == 0) {
      return 1;
    } 
  return 0;
}

void startup_late_hook(void) {
    unsigned char hash[crypto_hash_BYTES];
    //Enable system clock on all GPIO ports - page 254 https://www.pjrc.com/teensy/K20P64M72SF1RM.pdf
    GPIO_CONFIG = ((unsigned short)0x00043F82); // 0b1000011111110000010
    // Configure the trigger pin
    PORTA_PCR4 = ((unsigned short)0x00000143); // Enables GPIO | DSE | PULL_ENABLE | PULL_SELECT - page 227
    //Pin 26 (33 teensy pin)
    //Set the pin to input
    GPIOA_PDDR = ((unsigned short)0x0); 
    //look for the condition that indicates we want to jump to the application with offset
    //jump to application if jump flag is set and Pin 26 is not pulled low and application first sector is not erased
    if(IS_JUMP_TO_OFFSET_FLAG_SET() && ((GPIOA_PDIR >> 4)  & 0x01)!=0 && *FWSTARTADR != 0xFFFFFFFF) {
      __disable_irq();
      //Check if sha512 hash of currently loaded fw matches stored sha512 hash
      if (fwintegritycheck(hash)){
      //set peripherals back to normal then jump
      resetPeripherals();
      jumpToApplicationAt0x6060();
      } else {
        __enable_irq();
        eraseflash(); //Integrity check failed wipe all firmware
      }
  }
}
#ifdef __cplusplus
}
#endif

#define OKFWUPDATE           (0x80 | 0x74)
#define CPU_RESTART_ADDR (uint32_t *)0xE000ED0C
#define CPU_RESTART_VAL 0x5FA0004
#define CPU_RESTART() (*CPU_RESTART_ADDR = CPU_RESTART_VAL);
Adafruit_NeoPixel pixels = Adafruit_NeoPixel(1, 10, NEO_GRB + NEO_KHZ800);

void restartAndJumpToFirmware(int error) {
  if (error) {
    pixels.setPixelColor(0, pixels.Color(200,0,0));
    pixels.show();
  }
  SET_JUMP_FLAG();
  CLEAR_FWLOAD_FLAG();
  delay(2000);
  CPU_RESTART();
}

void restartAndJumpToBootloader(void) {
  pixels.setPixelColor(0, pixels.Color(200,0,0));
  pixels.show();
  CLEAR_JUMP_FLAG();
  SET_FWLOAD_FLAG();
  delay(2000);
  CPU_RESTART();
}

void initColor() {
  pixels.begin(); // This initializes the NeoPixel library.2
  pixels.setPixelColor(0, pixels.Color(150,150,150));
  pixels.show();
}


void setup() {
  #ifdef DEBUG
  delay(2000);
  #endif
  initColor();
}

void loop() {
  if (!digitalRead(33) || *FWSTARTADR == 0xFFFFFFFF) SET_FWLOAD_FLAG();
  if (IS_FWLOAD_FLAG_SET() ) { //If Trigger pin for bootloader is set (LOW) or FWLOAD flag is set try to load firmware
    #ifdef DEBUG
    Serial.println("FW FLAG SET"); 
    #endif 
    SET_JUMP_FLAG(); 
    CLEAR_FWLOAD_FLAG();
    while (!DONE) { 
    processpacket();
    }
  }
}

void processpacket () {
  unsigned char mesg[17000];
  int n;
  n = RawHID.recv(recv_buffer, wait); // 0 timeout = do not wait
    if (n > 0) {
      #ifdef DEBUG      
      Serial.println("Received Packet");
      #endif    
      if (recv_buffer[4] == OKFWUPDATE) {
          //Load Firmware
          hidprint("RECEIVED OKFWUPDATE");
          if (recv_buffer[5]==0xFF) //Not last packet
          {
          if (offsetindex <= (17000 - 57)) {
              memcpy(smesg+offsetindex, recv_buffer+6, 57);
              #ifdef DEBUG
              Serial.println("received=");
              byteprint(smesg+offsetindex, 57);
              #endif
              offsetindex = offsetindex + 57;
            } else {
              hidprint("Error firmware file block too large");
              restartAndJumpToFirmware(1);
              return;
            }
            return;
          } else { //last packet
            if (offsetindex != 0 && offsetindex <= (17000 - 57) && recv_buffer[5] <= 57) {
              memcpy(smesg+offsetindex, recv_buffer+6, recv_buffer[5]);
              #ifdef DEBUG
              Serial.print("last packet=");
              byteprint(smesg+offsetindex, recv_buffer[5]);
              #endif 
              offsetindex = offsetindex + recv_buffer[5];
              #ifdef DEBUG
              Serial.println("block=");
              byteprint(smesg, offsetindex);
              #endif 
             
             if (writtenblocks != 0) {
                if (crypto_verify_32(lastsigpart1, smesg) != 0 && crypto_verify_32(lastsigpart2, smesg+32) != 0) {
                 #ifdef DEBUG
                Serial.println("crypto_verify fail");
                delay(1000);
                #endif 
                  DONE = true;
                  return;
                }
              } 
              memcpy(lastsigpart1, smesg+65, 32);
              memcpy(lastsigpart2, smesg+97, 32);
              #ifdef DEBUG
              Serial.println("Signature=");
              byteprint(lastsigpart1, 32);
              byteprint(lastsigpart2, 32);
              #endif 
              if (crypto_sign_open(mesg,&mlen,smesg,offsetindex,pk) == 0) {
                #ifdef DEBUG
                Serial.println("Fw sig verify success");
                Serial.println("mesg=");
                byteprint(mesg, mlen);
                #endif
                writeflash(mesg, mlen);
                } else {
                  hidprint("Error firmware signature verify failed");
                  restartAndJumpToFirmware(1);
              }
            } else {
              hidprint("Error firmware file block too large");
              restartAndJumpToFirmware(1);
            }
          #ifdef DEBUG 
          Serial.print("Length= ");
          Serial.println(offsetindex);
          #endif 
          return;
        }
      } else {
        #ifdef DEBUG
        byteprint(recv_buffer,64);
        #endif
        hidprint("UNLOCKED BOOTLOADERv1");
      }
    }
 }

void writeflash(unsigned char* mesg, unsigned long long mlen) {
  uint8_t blockcount = (mesg[0] & 0xF0) >> 4;
  uint8_t totalblocks = mesg[0] & 0x0F;
  uint8_t sectorindex = (blockcount-1) * 8;
  unsigned char hash[crypto_hash_BYTES]; 
  #ifdef DEBUG 
  Serial.print("Blockcount= ");
  Serial.println(blockcount);
  Serial.print("Total Blocks=");
  Serial.println(totalblocks);
  Serial.print("Sector Index=");
  Serial.println(sectorindex);
  #endif 
  if (writtenblocks == 0) { //erase flash before writing new firmware
    eraseflash(); 
  } 
  uintptr_t adr = (unsigned long)FWSTARTADR + ((unsigned long)SECTORSIZE*(unsigned long)sectorindex);
  if (writtenblocks == totalblocks-1) { //Last block i.e. 1 of 10, all other blocks written
    mlen--; //discard previous blockcount
    adr = (unsigned long)FWSTARTADR;
    flashset_common(mesg+1, (unsigned long*)adr, mlen);
    #ifdef DEBUG 
    Serial.println("Last Block");
    #endif 
    offsetindex = 0;
    DONE = true;
    if (*FWSTARTADR == 0xFFFFFFFF) { //Something went wrong there is no program at jump address
      #ifdef DEBUG
      Serial.println("Error firmware load failed");
      #endif
      hidprint("Error firmware load failed");
      restartAndJumpToBootloader();
    } else {
      hidprint("SUCCESSFULLY LOADED FW");
      fwintegritycheck(hash); //create hash of firmware in hash buffer
      // Store new hash
      for (int i = 0; i < crypto_hash_BYTES; i++) { //write 64byte hash to eeprom
        eeprom_write_byte((unsigned char*)(2+i), hash[i]); // 0 used for bootloader jump flag, 1 used for fwload flag, 2-65 used for fw integrity hash
        #ifdef DEBUG
        Serial.print(eeprom_read_byte((unsigned char*)(2+i)), HEX);
        #endif
      }
      restartAndJumpToFirmware(0);
    }
  } else {
    mlen = mlen - 65; //discard previous signature and blockcount
    if (adr <= (unsigned long)FWENDADR && (writtenblocks == totalblocks-blockcount)) {
      #ifdef DEBUG 
        Serial.println("Not last Block");
        #endif 
        flashset_common(mesg+65, (unsigned long*)adr, mlen); 
        writtenblocks++;
    } else {
        hidprint("Error firmware file too large or out of order");
        restartAndJumpToBootloader();
    }
  }
  offsetindex = 0;
  hidprint("READY FOR NEXT BLOCK");
  return;
}

#ifdef DEBUG
void byteprint(uint8_t* bytes, int size) { 
  Serial.println();
  for (int i = 0; i < size; i++) {
    Serial.print(bytes[i], HEX);
    Serial.print(" ");
    }
  Serial.println();
}
#endif

void hidprint(char const * chars) { 
  int i=0;
  uint8_t resp_buffer[64] = {0};
  #ifdef DEBUG
  delay(wait);
  Serial.println(chars);
  #endif 
  while(*chars) {
  if (*chars == 0xFF) resp_buffer[i] = 0x00; //Empty flash sector is 0xFF
  else resp_buffer[i] = (uint8_t)*chars;
  chars++;
  i++;
  }
  RawHID.send(resp_buffer, 0);
  memset(resp_buffer, 0, sizeof(resp_buffer));
}


void flashset_common (uint8_t *ptr, unsigned long *adr, int len) {
  for( int z = 0; z <= len-4; z=z+4) {
    unsigned long data = (uint8_t)*(ptr+z+3) | ((uint8_t)*(ptr+z+2) << 8) | ((uint8_t)*(ptr+z+1) << 16) | ((uint8_t)*(ptr+z) << 24);
    flashwrite((unsigned long*)adr, &data);
    adr++;
  }
  return;
}

void flashget_common (uint8_t *ptr, unsigned long *adr, int len) {
  for( int z = 0; z <= len-4; z=z+4){
    *ptr = (uint8_t)((*(adr) >> 24) & 0xFF);
    ptr++;
    *ptr = (uint8_t)((*(adr) >> 16) & 0xFF);
    ptr++;
    *ptr = (uint8_t)((*(adr) >> 8) & 0xFF);
    ptr++;
    *ptr = (uint8_t)((*(adr) & 0xFF));
    ptr++;
    adr++;
  }
  return;
}

#ifdef DEBUG
void dumpflash(unsigned long readadr) {
  delay(1000);
  char temp[32];
    while (readadr <= (0x3FFFF)) { //Only dump used flash
      for (int i =0; i<=16380; i=i+4) { //16K blocks at a time
        sprintf (temp, "%.8X", *((unsigned int*)readadr));
        Serial.print(temp);
        readadr = readadr + 4;
        /*
        j++;
        delay(1);
        if (j==4) { //Format for comparison with HEX http://www.dlwrr.com/electronics/tools/hexview/hexview.html
          Serial.println(); 
          j=0;
        }
        */
      }
    Serial.println();
  }
}
#endif 

void flashwrite(uint32_t *adr, uint32_t *data) {
  if (adr>=FWSTARTADR) {//Protect Bootloader from being overwritten
      GET_ADDR(4,adr);
      while ((FTFL_FSTAT & 128) == 0) {}   // wait for previous commands to complete
      FTFL_FSTAT  = 48;
      FTFL_FCCOB7 = (uint8_t)*data; // enter the long word to be programmed
      FTFL_FCCOB6 = (uint8_t)(*data >> 8);
      FTFL_FCCOB5 = (uint8_t)(*data >> 16);
      FTFL_FCCOB4 = (uint8_t)(*data >> 24);
      FTFL_FCCOB3 = ((uint32_t)adr); // set address in flash
      FTFL_FCCOB2 = ((uint32_t)adr) >> 8;
      FTFL_FCCOB1 = ((uint32_t)adr) >> 16;
      FTFL_FCCOB0 = 6; // enter the command sequence
      __disable_irq();
      doram(&FTFL_FSTAT);
      __enable_irq();
    }
}

FASTRUN void doram(volatile uint8_t *ptr) {                                         
  *ptr = 128;
  while ((*ptr & 128) == 0) {}   // wait for previous commands to complete
}
