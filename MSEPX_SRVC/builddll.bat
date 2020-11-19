"C:\Program Files\Microsoft SDKs\Windows\v6.0A\bin\mc" -U RegValSvc.mc
"C:\Program Files\Microsoft SDKs\Windows\v6.0A\bin\rc" -r RegValSvc.rc
"D:\Program Files\Microsoft Visual Studio 10.0\VC\bin\link" -dll -noentry -out:RegValSvc.dll RegValSvc.res