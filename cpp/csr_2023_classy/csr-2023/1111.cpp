#include<bits/stdc++.h>
using namespace std;
const string password = "hunter";

int main()
{
    cout << "Please provide the password:" << endl;

    string user_password;
    cin >> user_password;

    if (user_password != password) {
      cout << "Wrong password." << endl;
      return 0;
    }
    cout<<"1111"<<endl;
    return 0;
}