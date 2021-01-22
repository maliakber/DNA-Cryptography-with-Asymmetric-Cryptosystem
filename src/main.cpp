/*  Ali Akber
    KUET, CSE 2k10
    Email - mail2aliakber@gmail.com  */
#include <bits/stdc++.h>
#include <gmp.h>
using namespace std;

typedef long long int           ll;

#define all(X)          X.begin(),X.end()
#define REVERSE(x)      reverse(x.begin(),x.end())

template<class T> inline void print(vector<T>v)
{
    int sz=v.size();
    for(int i=0;i<sz;i++)
        cout<<v[i]<<"\n";
    cout<<"\n";
}

// String conversion
string itos(ll N){stringstream ss;ss<<N;string str;str=ss.str();return str;}

#define pb          push_back
#define ff          first
#define ss          second
#define MP          make_pair
#define maxn        1000000

#define P(x) gmp_printf(" -- %Zd\n",x)
#define MODULUS_SIZE 1024                   /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8)         /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE/8) / 2)  /* This is the number of bytes in n and p */
//////////////////////////////////////////////////////////////////////
typedef struct {
    mpz_t n; /* Modulus */
    mpz_t e; /* Public Exponent */
} public_key;

typedef struct {
    mpz_t n; /* Modulus */
    mpz_t d; /* Private Exponent */
} private_key;

void generate_keys(private_key &prv, public_key &pub)
{
    // private key initialization
    mpz_init(prv.n);
    mpz_init(prv.d);
    // public key initialization
    mpz_init(pub.n);
    mpz_init(pub.e);

    char buf[BUFFER_SIZE];
    mpz_t phi; mpz_init(phi);
    mpz_t p; mpz_init(p);
    mpz_t q; mpz_init(q);
    mpz_t tmp1; mpz_init(tmp1);
    mpz_t tmp2; mpz_init(tmp2);

    srand(time(NULL));

    /* Instead of selecting e st. gcd(phi, e) = 1; 1 < e < phi, lets choose e
       first then pick p,q st. gcd(e, p-1) = gcd(e, q-1) = 1 */
    // We'll set e globally.  I've seen suggestions to use primes like 3, 17 or
    // 65537, as they make coming calculations faster.  Lets use 3.
    for(auto i = 0u; i < BUFFER_SIZE; i++)
        buf[i] = rand() % 0xFF;
    // Set the top two bits to 1 to ensure int(tmp) is relatively large
    buf[0] |= 0xC0;
    // Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
    buf[BUFFER_SIZE - 1] |= 0x01;
    // Interpret this char buffer as an int
    mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
    // Pick the next prime starting from that random number
    mpz_nextprime(pub.e, tmp1);

    /* Select p and q */
    /* Start with p */
    // Set the bits of tmp randomly
    for(auto i = 0u; i < BUFFER_SIZE; i++)
        buf[i] = rand() % 0xFF;
    // Set the top two bits to 1 to ensure int(tmp) is relatively large
    buf[0] |= 0xC0;
    // Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
    buf[BUFFER_SIZE - 1] |= 0x01;
    // Interpret this char buffer as an int
    mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
    // Pick the next prime starting from that random number
    mpz_nextprime(p, tmp1);
    /* Make sure this is a good choice*/
    mpz_mod(tmp2, p, pub.e);        /* If p mod e == 1, gcd(phi, e) != 1 */
    while(!mpz_cmp_ui(tmp2, 1))
    {
        mpz_nextprime(p, p);    /* so choose the next prime */
        mpz_mod(tmp2, p, pub.e);
    }

    /* Now select q */
    do {
        for(auto i = 0u; i < BUFFER_SIZE; i++)
            buf[i] = rand() % 0xFF;
        // Set the top two bits to 1 to ensure int(tmp) is relatively large
        buf[0] |= 0xC0;
        // Set the bottom bit to 1 to ensure int(tmp) is odd
        buf[BUFFER_SIZE - 1] |= 0x01;
        // Interpret this char buffer as an int
        mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
        // Pick the next prime starting from that random number
        mpz_nextprime(q, tmp1);
        mpz_mod(tmp2, q, pub.e);
        while(!mpz_cmp_ui(tmp2, 1))
        {
            mpz_nextprime(q, q);
            mpz_mod(tmp2, q, pub.e);
        }
    } while(mpz_cmp(p, q) == 0); /* If we have identical primes (unlikely), try again */

    /* Calculate n = p x q */
    mpz_mul(pub.n, p, q);

    /* Compute phi(n) = (p-1)(q-1) */
    mpz_sub_ui(tmp1, p, 1);
    mpz_sub_ui(tmp2, q, 1);
    mpz_mul(phi, tmp1, tmp2);

    /* Calculate d (multiplicative inverse of e mod phi) */
    if(mpz_invert(prv.d, pub.e, phi) == 0)
    {
        mpz_gcd(tmp1, pub.e, phi);
        printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
        printf("Invert failed\n");
    }

    mpz_set(prv.n, pub.n);

    printf("\np : "); P(p);
    printf("\nq : "); P(q);
    printf("\nPublic Key:\n");
    printf("n : "); P(pub.n);
    printf("e : "); P(pub.e);
    printf("\nPrivate Key:\n");
    printf("n : "); P(prv.n);
    printf("d : "); P(prv.d);
    return;
}
void encryption(mpz_t res,public_key pub,mpz_t M){
    mpz_powm(res,M,pub.e,pub.n);
}

void decryption(mpz_t res,private_key prv,mpz_t M){
    mpz_powm(res,M,prv.d,prv.n);
}
string to_str(int x)
{
    string str=itos(x);
    while(str.size()!=3)
        str="0"+str;
    return str;
}
string convert_bin(mpz_t x,int len)
{
    string ans;
    mpz_t rem,temp;
    mpz_init(rem);
    mpz_init(temp);
    mpz_set(temp,x);
    while(mpz_cmp_ui(x,0)>0)
    {
        mpz_mod_ui(rem,x,2);
        mpz_divexact_ui(x,x,2);
        if(mpz_cmp_ui(rem,0)==0)
            ans.push_back('0');
        else
            ans.push_back('1');
    }
    reverse(all(ans));
    mpz_set(x,temp);
    //cout<<ans.size()<<"***\n";
    int need=len-ans.size();
    string zero;
    zero.assign(need,'0');
    ans=zero+ans;
    //cout<<ans.size()<<"***\n";
    return ans;
}
string to_dna(string str)
{
    string ans;
    for(auto i=0u;str[i];i+=2)
    {
        if(str[i]=='0')
        {
            if(str[i+1]=='0')
                ans.push_back('A');
            else
                ans.push_back('C');
        }
        else
        {
            if(str[i+1]=='0')
                ans.push_back('G');
            else
                ans.push_back('T');
        }
    }
    return ans;
}

string dna_to_binary(string str)
{
    string ans;
    for(auto i=0u;str[i];i++)
    {
        if(str[i]=='A')
            ans+="00";
        else if(str[i]=='C')
            ans+="01";
        else if(str[i]=='G')
            ans+="10";
        else
            ans+="11";
    }
    return ans;
}

void binary_to_decimal(mpz_t val,string str)
{
    mpz_t mul;
    mpz_init(val);
    mpz_init(mul);
    mpz_set_str(val,"0",10);
    mpz_set_str(mul,"1",10);
    for(int i=str.size()-1;i>=0;i--)
    {
        if(str[i]=='1')
            mpz_add(val,val,mul);
        mpz_mul_ui(mul,mul,2);
    }
}

vector<int> get_dist(int n)
{
    vector<int>v;
    v.push_back(3);
    v.push_back(5);
    for(int i=2;i<n;i++)
    {
        v.push_back((v[i-1]+v[i-2])%20);
    }
    return v;
}

string rnd(int n)
{
    string str;
    for(int i=0;i<n;i++)
    {
        int p=rand()%4;
        if(p==0)
            str.push_back('A');
        else if(p==1)
            str.push_back('T');
        else if(p==2)
            str.push_back('G');
        else
            str.push_back('C');
    }
    return str;
}
int main()
{
    //freopen("E:/in.txt","r",stdin);
    //freopen("outRSA.txt","w",stdout);
    //double st=clock();
    private_key prv;
    public_key pub;
    generate_keys(prv,pub);

    string str;
    printf("\nEnter the text :\n");
    getline(cin,str);

    // converting plain string to decimal string
    string to_dec;
    for(auto i=0;str[i];i++)
    {
        to_dec+=to_str(str[i]);
    }
    printf("\nMessage in decimal\n");
    cout<<" -- "<<to_dec<<"\n";

    // making chunk
    vector<string>chunk;
    auto len=255u; //255

    // making same sized chunk
    if(to_dec.size()%len)
    {
        int rem=len-(to_dec.size()%len);
        string temp;
        temp.assign(rem,'0');
        to_dec=temp+to_dec;
    }
    //cout<<" -- "<<to_dec<<"\n";

    int cnt=(to_dec.size()/len);
    for(auto i=0;i<cnt;i++)
    {
        chunk.push_back(to_dec.substr(i*len,len));
    }

    printf("\nChunks :\n");
    print(chunk);


    // Encryption
    int sz=chunk.size();
    mpz_t encrypted_chunk[sz];
    for(auto i=0;i<sz;i++)
    {
        mpz_t M;
        mpz_init(encrypted_chunk[i]);
        mpz_init(M);
        mpz_set_str( M, chunk[i].c_str(), 10);

        encryption(encrypted_chunk[i],pub,M);

        printf("\nEncrypted text %d\n",i+1);
        P(encrypted_chunk[i]);
    }

    vector<string>bin_enc;
    for(auto i=0;i<sz;i++)
    {
        bin_enc.push_back(convert_bin(encrypted_chunk[i],MODULUS_SIZE));
        printf("\nbinary text %d\n",i+1);
        cout<<bin_enc[i]<<"\n";
    }

    vector<string>final;
    for(int i=0;i<sz;i++)
    {
        final.push_back(to_dna(bin_enc[i]));
        printf("\nDNA text %d\n",i+1);
        cout<<final[i]<<"\n";
    }

    vector<int>dist=get_dist(sz);
    string msg="";
    for(auto i=0;i<sz;i++)
    {
        msg+=final[i];
        msg+=rnd(dist[i]);
    }
    cout<<"\n -- Message : "<<msg<<"\n";

    // Decription

    vector<string>token;
    int msg_sz=MODULUS_SIZE/2;

    vector<int>dist1=get_dist(50);
    for(auto i=0u,j=0u;i<msg.size();i+=msg_sz)
    {
        token.push_back(msg.substr(i,msg_sz));
        i+=dist1[j++];
        printf("\nDNA text %d\n",j);
        cout<<token[j-1]<<"\n";
    }
    int sz1=token.size();

    vector<string>bin_dec;
    for(auto i=0;i<sz1;i++)
    {
        bin_dec.push_back(dna_to_binary(token[i]));
        printf("\nbinary text %d\n",i+1);
        cout<<bin_dec[i]<<"\n";
    }

    mpz_t val[sz1];
    for(auto i=0;i<sz1;i++)
    {
        binary_to_decimal(val[i],bin_dec[i]);
        printf("\ndecimal text %d\n",i+1);
        P(val[i]);
    }

    vector<string>dec_msg;
    for(auto i=0;i<sz1;i++)
    {
        mpz_t res; mpz_init(res);
        decryption(res,prv,val[i]);
        printf("\nDecrypted text %d\n",i+1);
        P(res);
        char * tmp = mpz_get_str(NULL,10,res);
        dec_msg.push_back(tmp);
    }

    for(auto i=0;i<sz1;i++)
    {
        if(dec_msg[i].size()<len)
        {
            int rem=len-dec_msg[i].size();
            string temp;
            temp.assign(rem,'0');
            dec_msg[i]=temp+dec_msg[i];
        }
        printf("\nDecrypted text %d\n",i+1);
        cout<<dec_msg[i]<<"\n";
    }

    string original_msg;
    for(auto i=0;i<sz1;i++)
        original_msg+=dec_msg[i];

    string final_str;
    for(auto i=0u;i<original_msg.size();i+=3)
    {
        string temp;
        temp=original_msg.substr(i,3);
        if(temp=="000")
            continue;
        final_str.push_back(stoi(temp));
    }
    cout<<"\nOriginal message :\n";
    cout<<final_str<<"\n";
    //cerr<<(double)(clock()-st)/CLOCKS_PER_SEC<<endl;
    return 0;
}
