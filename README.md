# RProtect
An extensible framework of active-defense system.  
Active-defense technology has been widely adopted by Chinese anti-virus companies, such as Qihoo 360, Micropoint, Tencent, Kingsoft, etc.  
The purpose of active-defense is to inform users if any software triggered any important API. In the early days, SSDT hooking was used to achieve this purpose, but with technology advances, KiSystemServiceRepeat hooking took the place and became the only solution adopted by current anti-virus softwares.  
Anyway, this technology is somewhat out of date for 2 reasons:  
1) Kernel hooking technique is against the modern OS defense mechanism, for example, PatchGuard in Windows x64;  
2) Ordinary users usually do not have the knowledge to authorize or prohibit the API calls.  
# Usage
Step 1. Load the driver with INSTDRV or any other tools.  
Step 2. Launch the GUI.  
# Also See
http://xiaonieblog.com/?post=73  
http://xiaonieblog.com/?post=75  
# Comments
1) This project if ONLY for testing. Be aware that kernel modifications may cause unstable or compatibility issues.  
2) The x64 version of this project CANNOT bypass PatchGuard. Pls add your own codes to do it, if you know the way, before testing it on Windows 64bit platform.
