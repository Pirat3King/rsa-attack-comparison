// ---------------------------------------------------------------------------
// Project: RSA Attack Comparison
// Description: Performs two different attacks on RSA encryption (brute force and factoring) 
//              and compares the time to complete each attack.
// Author: Pirat3King
// Date: 2023-03-23
// ---------------------------------------------------------------------------

#include <iostream>
#include <chrono>
#include <vector>

using namespace std;

// ---------------------------------------------------------------------------
// Function Prototypes
// ---------------------------------------------------------------------------

void printBanner();
void showMenu();
void readInput(long long& e, long long& n, long long& c);
unsigned long long modExp(unsigned long long a, long long e, unsigned long long b);
void primeFactors(long long x, long long& p, long long& q);
long long totient(long long p, long long q);
long long modInverse(long long  e, long long phiN);
long long attack1(long long  e, long long n, long long c);
long long attack2(long long  e, long long n, long long c, long long& p, long long& q, long long& d);

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main()
{
    long long e = 0, n = 0, c = 0, m = 0;
    
    int sel = 0;

    printBanner();

    do
    {
        showMenu();
        cin >> sel;

        switch (sel)
        {
            case 1: //Attack 1: Brute Force
            {
                readInput(e, n, c);             

                auto t1 = chrono::high_resolution_clock::now();
                m = attack1(e, n, c);
                auto t2 = chrono::high_resolution_clock::now();

                chrono::duration<double, milli> time = t2 - t1;

                cout << "\n--------------------Result-------------------------\n"
                        "Decrypted message (M): " << m << "\n"
                        "Time to run: " << time.count() << "ms\n" << endl;
                break;
            }

            case 2: //Attack 2: Factoring
            {
                long long p = 0, q = 0, d = 0;

                readInput(e, n, c);

                auto t1 = chrono::high_resolution_clock::now();
                m = attack2(e, n, c, p, q, d);
                auto t2 = chrono::high_resolution_clock::now();

                chrono::duration<double, milli> time = t2 - t1;

                cout << "\n--------------------Result-------------------------\n"
                        "Decrypted message (M): " << m << "\n"
                        "Primes:\n"
                        "\tp: " << p << "\n"
                        "\tq: " << q << "\n"
                        "Decryption exponent (d): " << d << "\n"
                        "Time to run: " << time.count() << "ms\n" << endl;
                break;
            }

            case 3:
                cout << "Goodbye" << endl;
                break;
                
            default:
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "\nERROR: Invalid option" << endl;
                break;
        }
    } while (sel != 3);

    return 0;
}


// ---------------------------------------------------------------------------
// Function Definitions
// ---------------------------------------------------------------------------

//Display banner
void printBanner()
{
    cout << "---------------------------------------------------\n"
            "            RSA Attack Time Comparison             \n"
            "---------------------------------------------------\n" << endl;
}

//Display program menu and prompt user selection
void showMenu()
{
    cout << "Choose an option below to continue:\n"
            "\t1) Attack 1: Brute Force M\n"
            "\t2) Attack 2: Factor N\n"
            "\t3) Quit\n\n"

            "Select Option: " << endl;
}

//Prompt and read user input for plaintext and key
void readInput(long long& e, long long& n, long long& c)
{
    cout << "--------------------Input--------------------------\n"
            "Enter the encryption exponent (e): ";
    cin >> e;

    cout << "Enter the RSA modulus (N): ";
    cin >> n;
    
    cout << "Enter the ciphertext (C): ";
    cin >> c;
}

//Modular exponentiation. Returns X such that A^e mod B = X
unsigned long long modExp(unsigned long long a, long long e, unsigned long long b)
{ 
    unsigned long long x = 1;
    
    a %= b; //update a if >= b

    while (e > 0)
    {
        if (e % 2 == 1)    //exponent is odd
            x = (x * a) % b;
        a = (a * a) % b;
        e /= 2;
    }
    return x;
}

//Find the prime factors of an integer, return by reference
void primeFactors(long long x, long long& p, long long& q)
{ 
    vector<long long> res;
    
    //halve until odd
    while (x % 2 == 0)
        x /= 2;

    for (int i = 3; i <= (sqrt(x)); i += 2)
    {
        //if x is divisible by i, add it to the list and divide
        while (x % i == 0)
        {
            res.push_back(i);
            x /= i;
        }
    }

    //handles final remainder if applicable
    if (x > 2)
        res.push_back(x);
    
    //Returns. Only 2 prime factors can exist
    p = res[0];
    q = res[1];
}

//Euler's Totient Function
long long totient(long long p, long long q)
{
    return (p - 1) * (q - 1);
}

//Extended Euclidian Algorithm to find the first modular multiplicative inverse d 
//ed + ny = ed (mod phiN) -> ed = 1 (mod phiN) 
long long modInverse(long long e, long long phiN)
{
    long long res = 0;
    long long d = 1, y = 0;
    int i = 1;
    
    long long a = e, b = phiN, t1 = 0, t2 = 0, q = 0;

    while (b != 0)
    {
        q = a / b;
        t1 = a % b;
        t2 = d + q * y;
        
        //Swaps
        d = y; 
        y = t2; 
       
        a = b; 
        b = t1;
       
        i = -i;
    }
    
    //If a == gcd(e,phiN) != 1, then no inverse exists
    if (a != 1)
        return 0;
    
    //Ensure a positive result
    if (i < 0)
        res = phiN - d;
    else
        res = d;
    return res;  
}

//Brute force M such that M^e mod N = C and M < N
long long attack1(long long e, long long n, long long c)
{
    for (long long m = 0; m < n; m++)
    {
        if (modExp(m, e, n) == c)
            return m;
    }
    return -1;
}

//Find M by factoring N and deriving d
long long attack2(long long  e, long long n, long long c, long long& p, long long& q, long long& d)
{
    //find coprime factors of N
    primeFactors(n, p, q);

    //find d such that d = e^-1(1 mod ø(N))
    d = modInverse(e, totient(p, q));

    //C^d mod N
    unsigned long long ptext = modExp(c, d, n);
    
    //Find M such that C^d mod N = M
    for (long long m = 0; m < n; m++)
    {
        if (ptext == m)
            return m;
    }
    return -1;
}