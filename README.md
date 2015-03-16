# RProtect
An extensible framework of active-defense system.<br><br>
Active-defense technology has been widely adopted by Chinese anti-virus companies, such as Qihoo 360, Micropoint, Tencent, Kingsoft, etc.<br>
The purpose of active-defense is to inform users if any software triggered any important API. In the early days, SSDT hooking was used to achieve this purpose, but with technology advances, KiSystemServiceRepeat hooking took the place and became the only solution adopted by current anti-virus softwares.<br><br>
Anyway, this technology is somewhat out of date for 2 reasons:<br>
1) Kernel hooking technique is against the modern OS defense mechanism, for example, PatchGuard in Windows x64;<br>
2) Ordinary users usually do not have the knowledge to authorize or prohibit the API calls.<br>
# Usage
Step 1. Load the driver with INSTDRV or any other tools.<br>
Step 2. Launch the GUI.<br>
# Also See
http://xiaonieblog.com/?post=73<br>
http://xiaonieblog.com/?post=75<br>
# Comments
1) This project if ONLY for testing. Be aware that kernel modifications may cause unstable or compatibility issues.<br>
2) The x64 version of this project CANNOT bypass PatchGuard. Pls add your own codes to do it, if you know the way, before testing it on Windows 64bit platform.
