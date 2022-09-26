#include <cstring>
#include <stdint.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>
// #include "../src/EncryptedArray.h"
// #include "../src/hypercube.h"

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include "Symmetric/SPN_Multi.h"

#ifdef USE_ZZX_POLY
#define PolyType ZZX
#else
#if (ALT_CRT)
#define PolyType AltCRT
#else
#define PolyType DoubleCRT
#endif
#endif

using namespace helib;
namespace std {} using namespace std;
namespace NTL {} using namespace NTL;

#define homDec
#define DEBUG
//#define homEnc
// 全局变量声明
long ROUND=14;
long BlockSize = 128;
long BlockByte = BlockSize/8;
// 分组数量
long nBlocks = 1;
static const uint8_t roundConstant = 0xCD; // x^7+x^6+x^3+x^2+1

// lm: I have set the parameters of idx = 0, 4
static long mValues[][15] = { 
//{ p, phi(m),  m,   d, m1,  m2, m3,   g1,    g2,   g3,ord1,ord2,ord3, c_m}
  { 2,  512,    771, 16,771,  0,  0,     5,    0,    0,-32,  0,  0, 100, 980}, // m=(3)*{257} :-( m/phim(m)=1.5 C=77 D=2 E=4
  { 2, 4096,   4369, 16, 17, 257, 0,   258, 4115,    0, 16,-16,  0, 100, 590}, // m=17*(257) :-( m/phim(m)=1.06 C=61 D=3 E=4
  { 2, 16384, 21845, 16, 17, 5, 257,  8996,17477,21591, 16,  4,-16,1600, 490}, // m=5*17*(257) :-( m/phim(m)=1.33 C=65 D=4 E=4
  { 2, 23040, 28679, 24, 17, 7, 241, 15184, 4098,28204, 16,  6,-10,1500, 430}, // m=7*17*(241) m/phim(m)=1.24    C=63  D=4 E=3
  { 2, 46080, 53261, 24, 17,13, 241, 43863,28680,15913, 16, 12,-10, 100, 1300}, // m=13*17*(241) m/phim(m)=1.15   C=69  D=4 E=3
  { 2, 64512, 65281, 48, 97,673,  0, 43073,22214,    0, 96,-14,  0, 100, 480}, // m=97*(673) :-( m/phim(m)=1.01  C=169 D=3 E=4
  {  2,  1728,  4095, 12,   7,   5,117,  2341,  3277, 3641,   6,   4,   6, 100, 200}, // m=(3^2)*5*7*{13} m/phim(m)=2.36 C=26 D=3 E=2 
  {  2, 34848, 45655, 44, 23,1985,  0, 33746, 27831, 0,  22,  36, 0, 100, 200}, // m=(5)*23*{397} m/phim(m)=1.31  C=100 D=2 E=2
  { 2, 49500, 49981, 30, 151, 331, 0,  6952, 28540,  0, 150,  11,0, 100, 200}, // m=151*(331) m/phim(m)=1        C=189 D=2 E=1  1650 slots
  { 2, 42336, 42799, 21, 127, 337,  0, 25276, 40133, 0, 126,  16,0, 200, 200}, // m=127*(337) m/phim(m)=1.01     C=161 D=2 E=0  2016 slots
  
};

void printState(Vec<uint8_t>& st);
// Encode plaintext/ciphertext bytes as native HE plaintext
void encodeTo1Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  long nAllBlocks = divc(data.length(),16); // ceil( data.length()/16 )
  long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.
  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<GF2X> slots(ea.size(), GF2X::zero());
    for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
      long blockShift = (i*blocksPerCtxt +j)*16;  // point to block
      for (long k=0; k<16; k++) {         // k is the byte number in this block
        long byteIdx= blockShift+ k;      // column orded within block
        if (byteIdx < data.length()) {
          long slotIdx = j + k*blocksPerCtxt;
          GF2XFromBytes(slots[slotIdx], &data[byteIdx], 1);// copy byte as poly
        }
      }
    }
    ea.encode(encData[i], slots);
  }
}

// Decode native HE plaintext as AES plaintext/ciphertext bytes
void decodeTo1Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // Check the size of the data array
  long nBytes = encData.length() * ea.size(); // total number of input bytes
  if (data.length()<=0 || data.length()>nBytes)
    data.SetLength(nBytes);
  long nAllBlocks = divc(data.length(),16);       // ceil( data.length()/16 )
  long blocksPerCtxt = ea.size() / 16;        // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);   // <= encData.length()

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.

  vector<GF2X> slots;
  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    ea.decode(slots, encData[i]);
    for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
      long blockShift = (i*blocksPerCtxt +j)*16;  // point to block
      for (long k=0; k<16; k++) {         // k is the byte number in this block
        long byteIdx= blockShift +k;      // column orded within block
        if (byteIdx < data.length()) {
          long slotIdx = j + k*blocksPerCtxt;
          BytesFromGF2X(&data[byteIdx], slots[slotIdx], 1);// copy poly as byte
        }
      }
    }
  }
}


void buildRoundConstant(Ctxt& encA,
			const EncryptedArrayDerived<PA_GF2>& ea)
{
  // char --> GF2X --> ZZX -->Ctxt 
  GF2X polyConstant;
  GF2XFromBytes(polyConstant, &roundConstant, 1);
  // cout << "----Round Constant: " << polyConstant << "  \n";
  vector<GF2X> slots(ea.size(), polyConstant);
  ZZX ZZXConstant;
  ea.encode(ZZXConstant, slots);
  encA.DummyEncrypt(ZZXConstant);
}

// run the AES key-expansion and then encrypt the expanded key.
void encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec)
{
    // Round Key length
    long round_key_length = BlockByte;
    // Compute the key expansion 
    long length_s = round_key_length * (ROUND+1);
    uint8_t roundKeySchedule[length_s];

    long blocksPerCtxt = ea.size() / BlockByte;

    // symKey.length() =16
    uint8_t encRoundKeySchedule[length_s];
    long nRoundKeys = KeyExpansion(encRoundKeySchedule, ROUND, BlockByte, symKey.data());
   if(key2dec)
    {
      // Change to Decrypt roundkey
      decRoundKey(roundKeySchedule, encRoundKeySchedule, ROUND, BlockByte);
    }
    else
    {
      for(long i=0; i<length_s; i++)
        roundKeySchedule[i] = encRoundKeySchedule[i];
    }
      // printf("roundKeySchedule---:\n");
      // for(int d=0;d<length_s; d++)
      // {
      //   cout<<d;
      //   printf(". %02x ;",roundKeySchedule[d]);
      // }
      // printf("\nroundKeySchedule---END!\n");
    
    // -------roundKeySchedule ---->  expanded ---> encode
 
    // Expand the key-schedule, copying each round key blocksPerCtxt times
    Vec<uint8_t> expanded(INIT_SIZE, nRoundKeys*blocksPerCtxt*BlockByte);
    for (long i=0; i<nRoundKeys; i++) {
      uint8_t* roundKey = &roundKeySchedule[16*i];
      for (long j=0; j<blocksPerCtxt; j++)
        memcpy(&expanded[16*(i*blocksPerCtxt +j)], roundKey, 16);
    }
    Vec<ZZX> encoded;
    encodeTo1Ctxt(encoded, expanded, ea);      // encode as HE plaintext

    {   
        Ctxt tmpCtxt(hePK);
        eKey.resize(encoded.length(), tmpCtxt);
    } // allocate space
    for (long i=0; i<(long)eKey.size(); i++) // encrypt the encoded key
        hePK.Encrypt(eKey[i], encoded[i]);
}




// Compute the constants for Sbox
static void buildLinEnc(vector<PolyType>& encLinTran,
			const EncryptedArrayDerived<PA_GF2>& ea)
{
  // encLinTran[0]: The constants only have nonzero entires in their slots corresponding
  // to bytes 3,7,11,15 of each blocks
  // encLinTran[1]: The constants only have zero entires in their slots corresponding
  // to bytes 0,4,8,12 of each blocks, others is 1;

  Vec<uint8_t> bytes(INIT_SIZE, ea.size());
  long blocksPerCtxt = ea.size() / 16;
  Vec<ZZX> tmp;

  memset(bytes.data(), 0, bytes.length());
  /*
    void *memset(void *s, int ch, size_t n);
    函数解释：将s中前n个字节 （typedef unsigned int size_t）用 ch 替换并返回 s
    讲bytes设置为0
  */
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 1;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[0] = tmp[0];

  memset(bytes.data(), 1, bytes.length());
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 0;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[1] = tmp[0];
}

// Compute the constants for Sbox
static void buildLinEnc2(vector<PolyType>& encLinTran,
			const EncryptedArrayDerived<PA_GF2>& ea)
{
  // encLinTran[0]: The constants only have nonzero entires in their slots corresponding
  // to bytes 3,7,11,15 of each blocks // 0001000100010001
  // encLinTran[1]: The constants only have nonzero entires in their slots corresponding
  // to bytes 2,6,10,14 of each blocks // 0010001000100010
  // encLinTran[1]: The constants only have zero entires in their slots corresponding
  // to bytes 01,45,89,1213 of each blocks, others is 1; //1100110011001100

  Vec<uint8_t> bytes(INIT_SIZE, ea.size());
  long blocksPerCtxt = ea.size() / 16;
  Vec<ZZX> tmp;

  memset(bytes.data(), 0, bytes.length());
  /*
    void *memset(void *s, int ch, size_t n);
    函数解释：将s中前n个字节 （typedef unsigned int size_t）用 ch 替换并返回 s
    讲bytes设置为0
  */
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 1;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[0] = tmp[0];

  memset(bytes.data(), 0, bytes.length());
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[2] = bptr[6] = bptr[10] = bptr[14] = 1;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[1] = tmp[0];

  memset(bytes.data(), 1, bytes.length());
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 0;
    bptr[2] = bptr[6] = bptr[10] = bptr[14] = 0;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[2] = tmp[0];
}

void decSboxFunc(Ctxt& c, vector<PolyType> encLinTran, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

  c.cleanUp();
  Ctxt c1(c), c2(c), c3(c), c4(c);
  ea.rotate1D(c1, 0, 1*rotAmount);
  ea.rotate1D(c2, 0, 2*rotAmount);
  ea.rotate1D(c3, 0, 3*rotAmount);
  ea.rotate1D(c4, 0,15*rotAmount);
  c1.cleanUp();  c2.cleanUp();  c3.cleanUp(); c4.cleanUp();
  
  c1.multiplyBy(c2);
  c += c1;
  c += c3;
  c += encA;

  const PolyType& p4 = encLinTran[0]; // 0001000100010001
  const PolyType& p123 = encLinTran[1]; //1110111011101110 

  c.multByConstant(p4);
  c4.multByConstant(p123);
  c += c4;

  c.cleanUp();
}

void decSboxFunc2(Ctxt& c, vector<PolyType> encLinTran, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

  const PolyType& p3 = encLinTran[0];   // 0001000100010001
  const PolyType& p2 = encLinTran[1];   // 0010001000100010
  const PolyType& p01 = encLinTran[2];   //1100110011001100

  c.cleanUp();
  Ctxt c1(c), c2(c), c15(c);
  ea.shift1D(c1, 0, 1*rotAmount);
  ea.shift1D(c2, 0, 2*rotAmount);
  ea.rotate1D(c15, 0,15*rotAmount);
  c1.cleanUp();  c2.cleanUp(); c15.cleanUp();
  
  c1.multiplyBy(c);
  c1 += c2;
  c1 += encA;

  Ctxt y3(c1);

  y3.multByConstant(p3);

  c15 += c1;
  c15.multByConstant(p2);
  Ctxt y2(c15); 
  ea.shift1D(c15, 0, 1*rotAmount); c15.cleanUp();
  y3 += c15;

  ea.rotate1D(c, 0, 14*rotAmount); c.cleanUp();
  c.multByConstant(p01);
  c += y2;
  c += y3;
  c.cleanUp();
}

void Linear_function(Ctxt& c, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
    long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

    c.cleanUp();
    // 循环左移   3  4  8 9 12 14
    // 即循环右移 13 12 8 7  4  2
    Ctxt c3(c), c4(c), c8(c), c9(c), c12(c), c14(c);
    ea.rotate1D(c3, 0, 13*rotAmount);
    ea.rotate1D(c4, 0, 12*rotAmount);
    ea.rotate1D(c8, 0, 8*rotAmount);
    ea.rotate1D(c9, 0, 7*rotAmount);
    ea.rotate1D(c12, 0, 4*rotAmount);
    ea.rotate1D(c14, 0, 2*rotAmount);
    
    c3.cleanUp();  c4.cleanUp(); c8.cleanUp();
    c9.cleanUp();  c12.cleanUp();  c14.cleanUp();

    c +=c3; 
    c +=c4; c +=c8; c +=c9; c +=c12;  c +=c14;
    c.cleanUp();
}

void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  for (long j=0; j<(long)eData.size(); j++) eData[j] += symKey[0];  // initial key addition
  // apply the symmetric rounds
  // (long)symKey.size()
  cout << "homSymDec Begin\n";
  cout << "eData.size() = " << eData.size() << "\n";
  cout << "symKey.size() = " << symKey.size() << "\n";

  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);

  vector<PolyType> encLinTran;
  encLinTran.resize(3, DoubleCRT(ea.getContext(), ea.getContext().fullPrimes())); 
  buildLinEnc2(encLinTran, ea);
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++){
    for (long j=0; j<(long)eData.size(); j++){
      // S Layer 
      for (long step=0; step<2; step++)
        decSboxFunc2(eData[j], encLinTran, encA, ea);
      // Linear Layer
      Linear_function(eData[j], ea);
      // Add round key
      eData[j] += symKey[i];
    }
  }

  // The last round is given below.
  // Linear layer is not here in the last round
    for (long j=0; j<(long)eData.size(); j++){
      
      // S Layer 
      for (long step=0; step<2; step++)
        decSboxFunc2(eData[j], encLinTran, encA, ea);
      // Add round key
      eData[j] += symKey[ROUND];
    }

  cout << "enc Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
}



// Perform sym encryption on plaintext bytes (ECB mode). The input are
// raw plaintext bytes, and the sym key encrypted under HE. The output
// is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
// array contains an encryption of the expanded sym key, the number of
// sym rounds is aesKey.size() -1.
// NOTE: This is a rather useless method, other than for benchmarking
void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo1Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }
  homSymDec(eData, symKey, ea); // do the real work
}

#if 1
int main(int argc, char **argv){

  // ArgMapping amap;

  long idx = 0;
  // amap.arg("sz", idx, "parameter-sets: toy=0 through huge=5");

  long c=3;
  // amap.arg("c", c, "number of columns in the key-switching matrices");

  bool packed=true;
  // amap.arg("packed", packed, "use packed bootstrapping");

  // amap.parse(argc, argv);
  if (idx>5) idx = 5;

  long p = mValues[idx][0];
  //  long phim = mValues[idx][1];
  long m = mValues[idx][2];

  long bits = mValues[idx][14];

  cout << "-----Test_Sym: c=" << c
      << ", packed=" << packed
      << ", m=" << m
      << ", Round=" << ROUND
      << endl;

  ofstream myfile;
  stringstream filename;
  filename << "result//SPN_1Ctxt_128bit_m = " << m << ", p = " << p
              << ", c = " << c << ", nRounds = " << ROUND << ".txt"; 
  
  setTimersOn();
  double tm = -GetTime();

  static const uint8_t aesPolyBytes[] = { 0x1B, 0x1 }; // X^8+X^4+X^3+X+1
  const GF2X aesPoly = GF2XFromBytes(aesPolyBytes, 2);
  cout << "-----X^8+X^4+X^3+X+1-------\n";  
  cout << "-----aesPoly: " << aesPoly << "\n";

  cout << "computing key-independent tables..." << std::flush;
  // Some code here to choose all the parameters, perhaps
  // using the fucntion FindM(...) in the FHEContext module  
  
  Context context(ContextBuilder<BGV>()
                .m(m)
                .p(p)
                .r(1)
                .bits(bits)
                .build());
  // initialize context
  

  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";

  //  context.getZMStar().printout();
  {
    IndexSet allPrimes(0,context.numPrimes()-1);
   cout <<"-----"<<context.numPrimes() << " total bitsize="
	<<context.logOfProduct(allPrimes)
	<<", security level: "<<context.securityLevel() << endl;

  myfile.open(filename.str(),ios::out);
  myfile << "[ m = " << m << ", p = " << p 
        << ", c = " << c << ", nRounds = " << ROUND << "]\n";
  myfile <<"1. "<<context.numPrimes()<<" primes. \n2. total bitsize = "
        <<context.logOfProduct(allPrimes)
        <<", \n3. security level = "<<context.securityLevel() 
        << ", \n4. nslots = "<<context.getZMStar().getNSlots()<<" ("
        << (context.getZMStar().getNSlots())/4<<" blocks) per ctxt\n";
  myfile.close();
  }
  long e = mValues[idx][3] /8; // extension degree
  cout << "-----"<<context.getZMStar().getNSlots()<<" slots ("
       << (context.getZMStar().getNSlots()/8)<<" blocks) per ctxt, red(p) = "
       << (context.getZMStar().getOrdP());
  if (packed)
    cout << ". x"<<e<<" ctxts";
  cout << endl;

  //----生成同态加密的公私钥， 
  cout << "computing key-dependent tables..." << std::flush;
  tm = -GetTime();
  SecKey secretKey(context);
  // construct a secret key structure associated with the context

  const PubKey& publicKey = secretKey;
  // an "upcast": SecKey is a subclass of PubKey

  secretKey.GenSecKey(); 
  // actually generate a secret key with Hamming weight w

  /*
  // Add key-switching matrices for the automorphisms that we need
  long ord = context.getZMStar().OrderOf(0);
  for (long i = 1; i < 16; i++) { // rotation along 1st dim by size i*ord/16
    long exp = i*ord/16;
    long val = PowerMod(context.getZMStar().ZmStarGen(0), exp, m); // val = g^exp

    // From s(X^val) to s(X)
    secretKey.GenKeySWmatrix(1, val);
    if (!context.getZMStar().SameOrd(0))
      // also from s(X^{1/val}) to s(X)
      secretKey.GenKeySWmatrix(1, InvMod(val,m));
  }
  */

  addSome1DMatrices(secretKey);
  // compute key-switching matrices that we need

  // addFrbMatrices(secretKey);      // Also add Frobenius key-switching
  // if (boot) { // more tables
  //   addSome1DMatrices(secretKey);   
  //   secretKey.genRecryptData();
  // }
  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";
  
  EncryptedArrayDerived<PA_GF2> ea(context, aesPoly, context.getAlMod());
  cout << "constuct an Encrypted array object ea that is.\n";

  long nslots = ea.size();
  // number of plaintext slots
  cout << "-----number of plaintext slots: " << nslots << "\n\n";
    
  GF2X rnd;
  //  生成秘钥 Vec_length = BlockByte
  Vec<uint8_t> symKey(INIT_SIZE, BlockByte); // 8*BlockByte
  random(rnd, 8*symKey.length());
  BytesFromGF2X(symKey.data(), rnd, symKey.length());

  // Choose random plain data
  
  Vec<uint8_t> ptxt(INIT_SIZE, nBlocks*BlockByte); //8*10
  Vec<uint8_t> symCtxt(INIT_SIZE, nBlocks*BlockByte);
  Vec<uint8_t> tmpBytes(INIT_SIZE, nBlocks*BlockByte);
  random(rnd, 8*ptxt.length());
  BytesFromGF2X(ptxt.data(), rnd, nBlocks*BlockByte);
  
  #ifdef DEBUG
  /*---Test Begin----*/
  unsigned char temp[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07,0x08  ,0x09  ,0x0A  ,0x0B  ,0x0C  ,0x0D  ,0x0E  ,0x0F};
  unsigned char temp2[16]= {0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77, 0x88  ,0x99  ,0xAA  ,0xBB  ,0xCC  ,0xDD  ,0xEE  ,0xFF};

  // cout << "-------symKey: \n";
  for(int d=0;d<BlockByte; d++)
  {
    // printf("%02x ",symKey.data()[d]);
    symKey.data()[d] = temp[d];
    // printf("[new] %02x ;",symKey.data()[d]);

  }
    // cout << "\n-------Ptxt: \n";
  for(int d=0;d<BlockByte; d++)
  {
    // printf("%02x ", ptxt.data()[d]);
    ptxt.data()[d] = temp2[d%BlockByte];
    // printf("[new] %02x ;",ptxt.data()[d]);
  }
  //cout << "-------Ptxt:  " << ptxt.data() << "\n\n";
  /*---Test END----*/
  #endif

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt) 
  uint8_t keySchedule[BlockByte * (ROUND+1)];
  KeyExpansion(keySchedule, ROUND, BlockByte, symKey.data());
  for (long i=0; i<nBlocks; i++) {
    Vec<uint8_t> tmp(INIT_SIZE, BlockByte);
    encryption(&symCtxt[BlockByte*i], &ptxt[BlockByte*i], keySchedule, ROUND);
  }
  // cout << "-----symkey random: " << symKey << "\n\n";
  cout << "  ptxt random= "; printState(ptxt); cout << endl;
  cout << "  encrypted symCtxt "; printState(symCtxt); cout << endl;
 
  vector<Ctxt> encryptedSymKey;
  // 2. Decrypt the symKey under the HE key

  #ifdef homDec
  cout << "computing symmetric round key tables..." << std::flush;
  tm = -GetTime();
  bool key2dec = true;
  encryptSymKey(encryptedSymKey, symKey, publicKey, ea, key2dec);
  tm += GetTime();  
  cout << "done in "<<tm<<" seconds\n";
  
  myfile.open(filename.str(), ios::app);
  myfile << "\nHomEnc symmetric round key done in "<<tm<<" seconds\n";

  // Perform homomorphic Symmetry
  cout << "homomorphic symmtric decryption Begin!\n"<< std::flush;
  vector< Ctxt > homEncrypted;
  tm = -GetTime();
  homSymDec(homEncrypted, encryptedSymKey, symCtxt, ea);
  tm += GetTime();
  cout << "Homomorphic symmtric decryption done in "<<tm<<" seconds\n";
  // homomorphic decryption
  Vec<ZZX> poly(INIT_SIZE, homEncrypted.size());
  for (long i=0; i<poly.length(); i++)
    secretKey.Decrypt(poly[i], homEncrypted[i]);
  decodeTo1Ctxt(tmpBytes, poly, ea);
 
  
  // Check that homSymDec(symCtxt) = ptxt succeeeded
  // symCtxt = symEnc(ptxt)
  if (ptxt != tmpBytes) {
    cout << "@ decryption error\n";
    if (ptxt.length()!=tmpBytes.length())
      cout << "  size mismatch, should be "<<ptxt.length()
	   << " but is "<<tmpBytes.length()<<endl;
    else {
      cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
      cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
      cout << " should be ptxt = "; printState(ptxt); cout << endl;
    }
  }
  else {
    cout << "Homomorphic symmtric decryption Finish! Done in "<<tm<<" seconds\n";
    //  Write file
    // myfile << "[homEncrypted] :  " << homEncrypted << "\n\n";
    { 
      myfile << "Homomorphic symmtric decryption Finish! done in "<<tm<<" seconds\n"; 
      myfile << "[After homomorphic decrypt.length]   " << tmpBytes.length() << "\n\n";
      myfile << "  input symCtxt = "; 
        myfile << "["; for (long i=0; i<symCtxt.length() && i<32; i++)  myfile << std::hex << std::setw(2) << (long) symCtxt[i] << " ";
        if (tmpBytes.length()>32) myfile << "..."; myfile << "]\n"; 
      myfile << "output tmpBytes = "; 
        myfile << "["; for (long i=0; i<tmpBytes.length() && i<32; i++) myfile << std::hex << std::setw(2) << (long) tmpBytes[i] << " ";
        if (tmpBytes.length()>32) myfile << "..."; myfile << "]\n";
      myfile << " should be ptxt = ";     
        myfile << "["; for (long i=0; i<ptxt.length() && i<32; i++)   myfile << std::hex << std::setw(2) << (long) ptxt[i] << " ";
        if (ptxt.length()>32) myfile << "...";  myfile << "]\n";
    }
      cout << "-------After homomorphic decrypt and Decode4MUT's length:   " << tmpBytes.length() <<"\n";
      cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
      cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
      cout << " should be ptxt = "; printState(ptxt); cout << endl;
  }
  myfile.close();
  cout << "\n-------Homomorphic symmtric decryption END! \n";
  resetAllTimers();
  #endif

}
#endif

#include <iomanip> 
void printState(Vec<uint8_t>& st)
{
  cerr << "[";
  for (long i=0; i<st.length() && i<32; i++) {
    cerr << std::hex << std::setw(2) << (long) st[i] << " ";
  }
  if (st.length()>32) cerr << "...";
  cerr << std::dec << "]";
}
