#include<bits/stdc++.h>
using namespace std;

char a[16]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};


signed main()
{
    for(int i=0;i<16;i++)
    { 
        for(int j=0;j<16;j++)
        {
            cout<<"b"<<char(34)<<char(92)<<"x"<<a[i]<<a[j]<<char(34)<<",";
            // printf("b'%c%c',",a[i],a[j]);
        }
    }


    return 0;
}