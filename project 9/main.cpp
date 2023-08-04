
#include"aes128.h"

int main() {

    string P = "23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739s23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8avkak192e37cdefkak192e37cdefvda23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739s23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8av23wrfhvsartrgdsu3h23wrfhvsartrgdsu3hrgvsfquyedscfdg12739svdac423av8avkak192e37cdefrgvsfquyedscfdg12739svdac423av8avkak192e37cdefkak192e37cdefvdac423av8avkak192e37cdefkak192e37cdefc423av8avkak192e37cdefkak192e37cdef";
    string k = "1234567890abcdef";
    string iv = "1324358675645wghjdbxvg";

    string C1, M1;
    cout << "***AES-128����***���ĳ��ȣ�" << P.size() << "\n\n";

    cout << "*CBCģʽ��\n";
    cout << "������...\n";
    timing(aes128, C1, P, k, iv, CTR_enc);
    //cout << "����������ģ�" << C1 << endl;

    cout << "������...\n";
    timing(aes128, M1, C1, k, iv, CTR_dec);
    //cout << "����������ģ�" << M1 << endl;
    cout << "\n";

    
    string C2, M2;
    cout << "*CTRģʽ��\n";
    cout << "������...\n";
    timing(aes128, C2, P, k, iv, CTR_enc);
    //cout << "����������ģ�" << C2 << endl;

    cout << "������...\n";
    timing(aes128, M2, C2, k, iv, CTR_dec);
    //cout << "����������ģ�" << M2 << endl;
    cout << "\n";
    return 0;
}
