http://pastebin.com/RU6A2UuB
	

    //http://waleedassar.blogspot.com - (@waleedassar)
    #include "stdafx.h"
    #include "windows.h"
     
     
    void ToLower(unsigned char* Pstr)
    {
            char* P=(char*)Pstr;
            unsigned long length=strlen(P);
            for(unsigned long i=0;i<length;i++) P[i]=tolower(P[i]);
            return;
    }
     
    int main(int argc, char* argv[])
    {
            //method 1
            HKEY HK=0;
            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,"HARDWARE\\ACPI\\DSDT\\VBOX__",0,KEY_READ,&HK)==ERROR_SUCCESS)
            {
                                    MessageBox(0,"VirtualBox detected","waliedassar",0);
                            ExitProcess(1);
            }
     
            //method 2 -- requires Guest Additions to be installed.
            HANDLE hF1=CreateFile("\\\\.\\VBoxMiniRdrDN",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,OPEN_EXISTING,0,0);
            if(hF1!=INVALID_HANDLE_VALUE)
            {
                    MessageBox(0,"VirtualBox detected","waliedassar",0);
                    ExitProcess(2);
            }
     
     
            //method 3 -- requires Guest Additions to be installed
            HMODULE hM1=LoadLibrary("VBoxHook.dll");
            if(hM1)
            {
                    MessageBox(0,"VirtualBox detected","waliedassar",0);
                    ExitProcess(3);
            }
     
            //method 4 -- requires Guest Additions to be installed
            HK=0;
            if( (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SOFTWARE\\Oracle\\VirtualBox Guest Additions",0,KEY_READ,&HK)) && HK)
            {
                    MessageBox(0,"VirtualBox detected","waliedassar",0);
                    RegCloseKey(HK);
                    ExitProcess(4);
            }
     
            //method 5
            HK=0;
            char* subkey="SYSTEM\\CurrentControlSet\\Enum\\IDE";
            if( (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE,subkey,0,KEY_READ,&HK)) && HK )
            {
                    unsigned long n_subkeys=0;
                    unsigned long max_subkey_length=0;
                    if(ERROR_SUCCESS==RegQueryInfoKey(HK,0,0,0,&n_subkeys,&max_subkey_length,0,0,0,0,0,0))
                    {
                            if(n_subkeys)  //Usually n_subkeys are 2
                            {
                                  char* pNewKey=(char*)LocalAlloc(LMEM_ZEROINIT,max_subkey_length+1);
                                      for(unsigned long i=0;i<n_subkeys;i++)  //Usually n_subkeys are 2
                                      {
                                                  memset(pNewKey,0,max_subkey_length+1);
                                                  HKEY HKK=0;
                              if(ERROR_SUCCESS==RegEnumKey(HK,i,pNewKey,max_subkey_length+1))
                                                      {
                                                               if((RegOpenKeyEx(HK,pNewKey,0,KEY_READ,&HKK)==ERROR_SUCCESS)  && HKK)
                                                               {
                                                                         unsigned long nn=0;
                                                                         unsigned long maxlen=0;
                                                                         RegQueryInfoKey(HKK,0,0,0,&nn,&maxlen,0,0,0,0,0,0);
                                         char* pNewNewKey=(char*)LocalAlloc(LMEM_ZEROINIT,maxlen+1);
                                                                             if(RegEnumKey(HKK,0,pNewNewKey,maxlen+1)==ERROR_SUCCESS)
	                                                                             {
                                                                                           HKEY HKKK=0;
                                                                                       if(RegOpenKeyEx(HKK,pNewNewKey,0,KEY_READ,&HKKK)==ERROR_SUCCESS)
                                                                                               {
                                                                                                    unsigned long size=0xFFF;
                                                                                                    unsigned char ValName[0x1000]={0};
                                                                                        if(RegQueryValueEx(HKKK,"FriendlyName",0,0,ValName,&size)==ERROR_SUCCESS)
                                                                                                            {
                                                                                                             ToLower(ValName);
                                                                                                             if(strstr((char*)ValName,"vbox"))
                                                                                                                     {
                                                                                                                    MessageBox(0,"VirtualBox detected","waliedassar",0);
                                                                                                                    ExitProcess(5);
                                                                                                                     }
                                                                                                            }
                                                                                                            RegCloseKey(HKKK);
                                                                                               }
                                                                             }
                                                                             LocalFree(pNewNewKey);
                                                                             RegCloseKey(HKK);
                                                               }
                                                      }
                                      }
                                      LocalFree(pNewKey);
                            }
                    }
                    RegCloseKey(HK);
            }
     
            //method 6
            HK=0;
            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System",0,KEY_READ,&HK)==ERROR_SUCCESS)
            {
                    unsigned long type=0;
                    unsigned long size=0x100;
                    char* systembiosversion=(char*)LocalAlloc(LMEM_ZEROINIT,size+10);
                    if(ERROR_SUCCESS==RegQueryValueEx(HK,"SystemBiosVersion",0,&type,(unsigned char*)systembiosversion,&size))
                    {
                              ToLower((unsigned char*)systembiosversion);
                              if(type==REG_SZ||type==REG_MULTI_SZ)
                              {
                                              if(strstr(systembiosversion,"vbox"))
                                              {
                                                                            MessageBox(0,"VirtualBox detected","waliedassar",0);
                                                                            ExitProcess(6);
                                              }
                              }
                    }
                    LocalFree(systembiosversion);
     
                    type=0;
                    size=0x200;
                    char* videobiosversion=(char*)LocalAlloc(LMEM_ZEROINIT,size+10);
                    if(ERROR_SUCCESS==RegQueryValueEx(HK,"VideoBiosVersion",0,&type,(unsigned char*)videobiosversion,&size))
                    {
                            if(type==REG_MULTI_SZ)
                            {
                                    char* video=videobiosversion;
                                    while(*(unsigned char*)video)
                                    {
                                            ToLower((unsigned char*)video);
                                            if(strstr(video,"oracle")||strstr(video,"virtualbox") )
                                            {
                                                                            MessageBox(0,"VirtualBox detected","waliedassar",0);
                                                                            ExitProcess(6);
                                            }
                                            video=&video[strlen(video)+1];
                                    }
                            }
                    }
                    LocalFree(videobiosversion);
                    RegCloseKey(HK);
            }
            //method 7 - requires guest additions to be installed.
            HANDLE hxx=CreateFile("\\\\.\\pipe\\VBoxTrayIPC",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
            if(hxx!=INVALID_HANDLE_VALUE)
            {
                            MessageBox(0,"VirtualBox detected","waliedassar",0);
                            CloseHandle(hxx);
                            ExitProcess(7);
            }
            //method 8 - requires guest additions installed
            HWND hY1=FindWindow("VBoxTrayToolWndClass",0);
            HWND hY2=FindWindow(0,"VBoxTrayToolWnd");
            if(hY1 || hY2)
            {
                    MessageBox(0,"VirtualBox detected","waliedassar",0);
                    ExitProcess(8);
            }
           
           //method 9
           unsigned long pnsize=0x1000;
           char* provider=(char*)LocalAlloc(LMEM_ZEROINIT,pnsize);
           int retv=WNetGetProviderName(WNNC_NET_RDR2SAMPLE,provider,&pnsize);
           if(retv==NO_ERROR)
           {
                    if(lstrcmpi(provider,"VirtualBox Shared Folders")==0)
                    {
                            MessageBox(0,"VirtualBox detected","waliedassar",0);
                            ExitProcess(9);
                    }
           }
           return 0;
    }

