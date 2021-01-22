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
struct public_key {
	mpz_t n;
	mpz_t g;
	mpz_t h;
};

struct private_key {
	mpz_t n;
	mpz_t g;
	mpz_t h;
	mpz_t x;
};

void get_random_n_bits(mpz_t r, size_t bits)
{
	size_t size = (size_t) ceilf(bits/8);
	char *buffer = (char*) malloc(sizeof(char)*size);
	for(int i = 0; i < size; i++)
        buffer[i] = rand() % 0xFF;
	mpz_import (r, size,1,sizeof(char), 0,0, buffer);
	free(buffer);
}

void get_random_n (mpz_t r, mpz_t max) {
	do {
		get_random_n_bits(r,mpz_sizeinbase(max,2));
	} while (mpz_cmp(r,max)>=0);
}

void get_random_n_prime (mpz_t r, mpz_t max) {
	do {
		get_random_n_bits(r,mpz_sizeinbase(max,2));
		mpz_nextprime(r,r);
	} while (mpz_cmp(r,max)>=0);
}

void generate_keys(private_key &prv, public_key &pub)
{
    mpz_init(prv.n);
    mpz_init(prv.g);
    mpz_init(prv.h);
    mpz_init(prv.x);


	mpz_init(pub.n);
	mpz_init(pub.g);
	mpz_init(pub.h);

	/* n is a large prime */
	get_random_n_bits(prv.n,MODULUS_SIZE);
	mpz_nextprime(prv.n,prv.n);

	/* Get some random x < n */
	get_random_n(prv.x,prv.n);

	/* g is the generator */
	get_random_n_prime(prv.g,prv.n);

	/* h = g^x (mod n) */
	mpz_powm(prv.h,prv.g,prv.x,prv.n);

	mpz_set(pub.n,prv.n);
	mpz_set(pub.g,prv.g);
	mpz_set(pub.h,prv.h);

	printf("Keys :\n");
	printf("n : "); P(prv.n);
	printf("g : "); P(prv.g);
	printf("h : "); P(prv.h);
	printf("x : "); P(prv.x);
}
void encryption(mpz_t c1, mpz_t c2,mpz_t msg,public_key pub){
    mpz_t y,s;
	mpz_init(y);
	mpz_init(s);
	mpz_init(c1);
	mpz_init(c2);

	get_random_n(y,pub.n);

	/* s = h^y (mod n) */
	mpz_powm(s,pub.h,y,pub.n);

	/* c1 = g^y (mod n) */
	mpz_powm(c1,pub.g,y,pub.n);

	/* c2 = msg * s (mod n) */
	mpz_mul(c2,msg,s);
	mpz_mod(c2,c2,pub.n);

}

void decryption(mpz_t msg,mpz_t c1,mpz_t c2,private_key prv){
    mpz_t s,inv_s;
	mpz_init(s);
	mpz_init(inv_s);

	/* s = c1^x */
	mpz_powm(s,c1,prv.x,prv.n);

	/* inv_s = s^{-1} */
	mpz_invert(inv_s,s,prv.n);

	/* msg = c2 inv_s */
	mpz_mul(msg,c2,inv_s);
	mpz_mod(msg,msg,prv.n);
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
    for(int i=0;str[i];i+=2)
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
    for(int i=0;str[i];i++)
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
    v.push_back(1);
    v.push_back(1);
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
    //freopen("outElgamal.txt","w",stdout);
    //double st=clock();
    int i,j,k,l,m,n;
    private_key prv;
    public_key pub;
    generate_keys(prv,pub);

    string str;
    printf("\nEnter the text :\n");
    getline(cin,str);

    // converting plain string to decimal string
    string to_dec;
    for(i=0;str[i];i++)
    {
        to_dec+=to_str(str[i]);
    }
    //printf("\nMessage in decimal\n");
    //cout<<" -- "<<to_dec<<"\n";

    // making chunk
    vector<string>chunk;
    int len=255; //255

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
    for(i=0;i<cnt;i++)
    {
        chunk.push_back(to_dec.substr(i*len,len));
    }

    printf("\nChunks :\n");
    print(chunk);


    // Encryption
    int sz=chunk.size()*2;
    mpz_t encrypted_chunk[sz];
    for(i=0;i<sz/2;i++)
    {
        mpz_t M;
        mpz_init(encrypted_chunk[i*2]);
        mpz_init(encrypted_chunk[i*2+1]);
        mpz_init(M);
        mpz_set_str( M, chunk[i].c_str(), 10);

        encryption(encrypted_chunk[i*2],encrypted_chunk[i*2+1],M,pub);

        printf("\nEncrypted text %d\n",i+1);
        printf("C1: ");P(encrypted_chunk[i*2]);
        printf("C2: ");P(encrypted_chunk[i*2+1]);
    }

    vector<string>bin_enc;
    for(i=0;i<sz;i++)
    {
        bin_enc.push_back(convert_bin(encrypted_chunk[i],MODULUS_SIZE));
        //cout<<bin_enc[i]<<"\n";
    }

    vector<string>final;
    for(int i=0;i<sz;i++)
    {
        final.push_back(to_dna(bin_enc[i]));
    }

    vector<int>dist=get_dist(sz);
    string msg="";
    for(i=0;i<sz;i++)
    {
        msg+=final[i];
        msg+=rnd(dist[i]);
    }
    cout<<"\n -- Message : "<<msg<<"\n";

    // Decription

    vector<string>token;
    int msg_sz=MODULUS_SIZE/2;

    vector<int>dist1=get_dist(50);
    for(i=0,j=0;i<msg.size();i+=msg_sz)
    {
        token.push_back(msg.substr(i,msg_sz));
        i+=dist1[j++];
    }
    int sz1=token.size();

    vector<string>bin_dec;
    for(i=0;i<sz1;i++)
    {
        bin_dec.push_back(dna_to_binary(token[i]));
        //cout<<bin_dec[i]<<"\n";
    }

    mpz_t val[sz1];
    for(i=0;i<sz1;i++)
    {
        binary_to_decimal(val[i],bin_dec[i]);
        //P(val[i]);
    }

    vector<string>dec_msg;
    for(i=0;i<sz1;i+=2)
    {
        mpz_t res; mpz_init(res);
        decryption(res,val[i],val[i+1],prv);
        //printf("\nDecrypted text %d\n",i+1);
        //P(res);
        char * tmp = mpz_get_str(NULL,10,res);
        dec_msg.push_back(tmp);
    }

    for(i=0;i<sz1/2;i++)
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
    for(i=0;i<sz1/2;i++)
      original_msg+=dec_msg[i];

    string final_str;
    j=original_msg.size();
    for(i=0;i<j;i+=3)
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
