
#include"aes128.h"

int main() {

    string P = "23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739s23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8avkak192e37cdefkak192e37cdefvda23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739s23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8avkak192e37cdefkak192e37cdefvdac423av8avkak192e37cdefkak192e37cdefc423av8avkak192e37cdefkak192e37cdef";
    string k = "1234567890abcdef";
    string iv = "1324358675645wghjdbxvg";

    string C1, M1;
    cout << "***AES-128测试***明文长度：" << P.size() << "\n\n";

    cout << "*CBC模式：\n";
    cout << "加密中...\n";
    timing(aes128, C1, P, k, iv, CTR_enc);
    //cout << "加密输出密文：" << C1 << endl;

    cout << "解密中...\n";
    timing(aes128, M1, C1, k, iv, CTR_dec);
    //cout << "解密输出明文：" << M1 << endl;
    cout << "\n";

    
    string C2, M2;
    cout << "*CTR模式：\n";
    cout << "加密中...\n";
    timing(aes128, C2, P, k, iv, CTR_enc);
    //cout << "加密输出密文：" << C2 << endl;

    cout << "解密中...\n";
    timing(aes128, M2, C2, k, iv, CTR_dec);
    //cout << "解密输出明文：" << M2 << endl;
    cout << "\n";
    return 0;
}
