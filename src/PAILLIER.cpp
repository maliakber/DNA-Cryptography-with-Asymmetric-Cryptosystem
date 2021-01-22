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
typedef struct
{
	int bits;  /* e.g., 1024 */
	mpz_t n;   /* public modulus n = p * q */
	mpz_t g;   /* g = n + 1, when p , q are equivalent length */
	mpz_t n_squared; /* cached to avoid recomputing */
} paillier_public_key;

typedef struct
{
	mpz_t lambda;    /* lambda = lcm(p-1,q-1) */
	mpz_t mu;        /* mu = (L (g^lambda mod n^2 ))^-1 mod n */
} paillier_private_key;

void init_rand(gmp_randstate_t rand,
               int bytes)
{
	void* buf;
	mpz_t s;

	buf = malloc(bytes);

	gmp_randinit_default(rand);
	mpz_init(s);
	mpz_import(s, bytes, 1, 1, 0, 0, buf);
	gmp_randseed(rand, s);

	free(buf);
}

void paillier_key_generation(int modulusbits,
                             paillier_public_key &pub,
                             paillier_private_key &prv)
{
    mpz_t p;
	mpz_t q;
	gmp_randstate_t rand;

	/* initialize our integers */

	mpz_init(pub.n);
	mpz_init(pub.g);
	mpz_init(pub.n_squared);

	mpz_init(prv.lambda);
	mpz_init(prv.mu);

	mpz_init(p);
	mpz_init(q);

	/* pick random (modulusbits/2)-bit primes p and q */

	init_rand(rand, modulusbits / 8 + 1);
	do
	{
		do
			mpz_urandomb(p, rand, modulusbits / 2);
		while( !mpz_probab_prime_p(p, 10) );

		do
			mpz_urandomb(q, rand, modulusbits / 2);
		while( !mpz_probab_prime_p(q, 10) );

		/* compute the public modulus n = p q */

		mpz_mul(pub.n, p, q);
	} while( !mpz_tstbit(pub.n, modulusbits - 1) );

	printf("p :"); P(p);
	printf("\nq :"); P(q);

	mpz_mul(pub.n_squared, pub.n, pub.n);
	mpz_add_ui((pub).g, (pub).n, 1);
	(pub).bits = modulusbits;

	/* compute the private key lambda = lcm(p-1,q-1) */

	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_lcm(prv.lambda, p, q);
    mpz_powm(prv.mu, pub.g, prv.lambda, pub.n_squared);
	mpz_sub_ui(prv.mu, prv.mu, 1);
	mpz_div(prv.mu, prv.mu, pub.n);
	mpz_invert(prv.mu, prv.mu, pub.n);


	printf("\nPublic key :\n");
	printf("\nn :"); P(pub.n);
	printf("\ng :"); P(pub.g);

	printf("\nPrivate key :\n");
	printf("\nlambda :"); P(prv.lambda);
	printf("\nmu     :"); P(prv.mu);
}

void paillier_encryption(   mpz_t &res,
                            paillier_public_key pub,
                            mpz_t pt  )
{
	mpz_t r;
	gmp_randstate_t rand;
	mpz_t x;

	/* pick random blinding factor */

	mpz_init(r);
 	init_rand(rand, pub.bits / 8 + 1);
	do
		mpz_urandomb(r, rand, pub.bits);
	while( mpz_cmp(r, pub.n) >= 0 );

	/* compute ciphertext */

    mpz_init(res);

	mpz_init(x);
	mpz_powm(res, pub.g, pt, pub.n_squared);
	mpz_powm(x, r, pub.n, pub.n_squared);

	mpz_mul(res, res, x);
	mpz_mod(res, res, pub.n_squared);
}

void paillier_decryption(   mpz_t &res,
							paillier_public_key pub,
							paillier_private_key prv,
							mpz_t ct )
{
	mpz_init(res);

	mpz_powm(res, ct, prv.lambda, pub.n_squared);
	mpz_sub_ui(res, res, 1);
	mpz_div(res, res, pub.n);
	mpz_mul(res, res, prv.mu);
	mpz_mod(res, res, pub.n);
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
    int need=len*2-ans.size();
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
    //freopen("outPaillier.txt","w",stdout);
    //double st=clock();
    int i,j,k,l,m,n,bit=1024;
    paillier_private_key prv;
    paillier_public_key pub;
    paillier_key_generation(bit,pub,prv);

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
    int sz=chunk.size();
    mpz_t encrypted_chunk[sz];
    for(i=0;i<sz;i++)
    {
        mpz_t M;
        mpz_init(encrypted_chunk[i]);
        mpz_init(M);
        mpz_set_str( M, chunk[i].c_str(), 10);

        paillier_encryption(encrypted_chunk[i],pub,M);

        printf("\nEncrypted text %d\n",i+1);
        P(encrypted_chunk[i]);
    }

    vector<string>bin_enc;
    for(i=0;i<sz;i++)
    {
        bin_enc.push_back(convert_bin(encrypted_chunk[i],bit));
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
    int msg_sz=MODULUS_SIZE;

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
    }

    mpz_t val[sz1];
    for(i=0;i<sz1;i++)
    {
        binary_to_decimal(val[i],bin_dec[i]);
    }

    vector<string>dec_msg;
    for(i=0;i<sz1;i++)
    {
        mpz_t res;
        paillier_decryption(res,pub,prv,val[i]);
        //printf("\nDecrypted text %d\n",i+1);
        //P(res);
        char * tmp = mpz_get_str(NULL,10,res);
        dec_msg.push_back(tmp);
    }

    for(i=0;i<sz1;i++)
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
    for(i=0;i<sz1;i++)
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
