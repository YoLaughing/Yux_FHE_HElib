#include <cstring>
#include <stdint.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include "../symmetric/spn-multi.h"
#include "params.h"

using namespace helib;
using namespace std;
using namespace NTL;

static long nBlocks = 12;

// lm: I have set the parameters of idx = 0, 4
static long mValues[][15] = { 
//{ p, phi(m),  m,   d, m1,  m2, m3,   g1,    g2,   g3,ord1,ord2,ord3, c_m}
  { 2,  512,    771, 16,771,  0,  0,     5,    0,    0,-32,  0,  0, 100, 500}, // m=(3)*{257} :-( m/phim(m)=1.5 C=77 D=2 E=4
  { 2, 4096,   4369, 16, 17, 257, 0,   258, 4115,    0, 16,-16,  0, 100, 590}, // m=17*(257) :-( m/phim(m)=1.06 C=61 D=3 E=4
  { 2, 16384, 21845, 16, 17, 5, 257,  8996,17477,21591, 16,  4,-16,1600, 490}, // m=5*17*(257) :-( m/phim(m)=1.33 C=65 D=4 E=4
  { 2, 23040, 28679, 24, 17, 7, 241, 15184, 4098,28204, 16,  6,-10,1500, 620}, //430 m=7*17*(241) m/phim(m)=1.24    C=63  D=4 E=3
  { 2, 46080, 53261, 24, 17,13, 241, 43863,28680,15913, 16, 12,-10, 100, 530}, //620 // m=13*17*(241) m/phim(m)=1.15   C=69  D=4 E=3
  { 2, 64512, 65281, 48, 97,673,  0, 43073,22214,    0, 96,-14,  0, 100, 480}, // m=97*(673) :-( m/phim(m)=1.01  C=169 D=3 E=4
  { 2,  1728,  4095, 12,   7,   5,117,  2341,  3277, 3641,   6,   4,   6, 100, 200}, // m=(3^2)*5*7*{13} m/phim(m)=2.36 C=26 D=3 E=2 
  { 2, 34848, 45655, 44, 23,1985,  0, 33746, 27831, 0,  22,  36, 0, 100, 200}, // m=(5)*23*{397} m/phim(m)=1.31  C=100 D=2 E=2
  { 2, 49500, 49981, 30, 151, 331, 0,  6952, 28540,  0, 150,  11,0, 100, 200}, // m=151*(331) m/phim(m)=1        C=189 D=2 E=1  1650 slots
  { 2, 42336, 42799, 21, 127, 337,  0, 25276, 40133, 0, 126,  16,0, 200, 200}, // m=127*(337) m/phim(m)=1.01     C=161 D=2 E=0  2016 slots
};


class Transcipher4
{
public:

// Encode plaintext/ciphertext bytes as native HE plaintext
void encodeTo4Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea);

// Decode native HE plaintext as AES plaintext/ciphertext bytes
void decodeTo4Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea);

void buildRoundConstant(Ctxt& encA,
			const EncryptedArrayDerived<PA_GF2>& ea);

// run the AES key-expansion and then encrypt the expanded key.
void encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec);

void decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea);

void decLinearFunc(vector<Ctxt>& eData, long begin, const EncryptedArrayDerived<PA_GF2>& ea);

void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea);

// Perform sym encryption on plaintext bytes (ECB mode). The input are
// raw plaintext bytes, and the sym key encrypted under HE. The output
// is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
// array contains an encryption of the expanded sym key, the number of
// sym rounds is aesKey.size() -1.
// NOTE: This is a rather useless method, other than for benchmarking
void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);

void encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea);

void encLinearFunc(vector<Ctxt>& eData, long begin, const EncryptedArrayDerived<PA_GF2>& ea);

void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea);

void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);

};
