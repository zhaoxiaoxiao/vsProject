// Encrypt.h: interface for the CEncrypt class.
//
//////////////////////////////////////////////////////////////////////

#if !defined ENCRYPT_H
#define ENCRYPT_H

//#ifndef _AES_H
//#define _AES_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif
//#include "utility/common/mwcore_export.h"

namespace UTI{
namespace COM{

typedef struct
{
    uint32 erk[64];     /* encryption round keys */
    uint32 drk[64];     /* decryption round keys */
    int nr;             /* number of rounds */
} aes_context;

class  CEncrypt
{
public:
    CEncrypt();
    virtual ~CEncrypt();

    //ucInput开辟的缓冲大小尽量是16的整数倍，若不是16的整数倍，算法会在后面强制补0
    //ucOutPut的大小要是16的整数倍最好是与ucInput的缓冲大小一致
    //ucKey的长度必须为16字节
    //返回>0:成功,表示密文的长度(16的整数倍)，返回-1:错误。
    int Encrypt(unsigned char *ucInput, unsigned int nInputLen, unsigned char *ucKey, unsigned char *ucOutput);

    //ucInput开辟的缓冲大小尽量是16的整数倍
    //nInputLen必须是16的整数倍
    //ucOutput最终返回长度可能不是原长度，因为后面有补0
    //ucKey的长度必须为16字节
    //返回>0:成功,表示明文的长度(16的整数倍)，返回-1:错误。
    int Decrypt(unsigned char *ucInput, unsigned int nInputLen, unsigned char *ucKey, unsigned char *ucOutput);

private:
    void aes_gen_tables(void);
    int  aes_set_key(aes_context *ctx, uint8 *key, int nbits);
    void aes_encrypt(aes_context *ctx, uint8 input[16], uint8 output[16]);
    void aes_decrypt(aes_context *ctx, uint8 input[16], uint8 output[16]);
private:
    int do_init;
    int KT_init;
    uint32 KT0[256];
    uint32 KT1[256];
    uint32 KT2[256];
    uint32 KT3[256];
    /* forward S-box & tables */

    uint32 FSb[256];
    uint32 FT0[256];
    uint32 FT1[256];
    uint32 FT2[256];
    uint32 FT3[256];

    /* reverse S-box & tables */

    uint32 RSb[256];
    uint32 RT0[256];
    uint32 RT1[256];
    uint32 RT2[256];
    uint32 RT3[256];

    /* round constants */
    uint32 RCON[10];
};
}} //end namespace

//入参：szKey      密钥(注意:只支持明文字符串,且必须是16个字节)
//入参：szSrcStr   需要加密的字符串(注意:只支持明文字符串)      
//出参：szDestStr  加密后的字符串(16进制的字符串)
//返回值：>=0:密文的长度 <0:失败
int  MW_AESEncodePwd(const char* szKey, const char* szSrcStr, char* szDestStr);

//入参：szKey      密钥(注意:只支持明文字符串,且必须是16个字节)
//入参：szSrcStr   密文字符串(16进制的字符串)      
//出参：szDestStr  解密后的字符串
//返回值：>=0:明文的长度 <0:失败
int  MW_AESDecodePwd(const char* szKey, const char* szSrcStr, char* szDestStr);
#endif // !defined(AFX_ENCRYPT_H__5510E115_7462_490E_B1DA_FF812A8E08FA__INCLUDED_)
