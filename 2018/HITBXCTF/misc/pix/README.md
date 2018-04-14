```
$ zsteg ./aee487a2-49cd-4f1f-ada6-b2d398342d99.SteinsGate 
imagedata           .. text: " !#865   "
b1,r,msb,xy         .. text: "y5b@2~2t"
b1,rgb,lsb,xy       .. file: Keepass password database 2.x KDBX
b2,r,msb,xy         .. text: "\rP`I$X7D"
b2,bgr,lsb,xy       .. text: "b;d'8H~M"
b4,g,msb,xy         .. text: ";pTr73& dvG:"
```
```
$ zsteg -E b1,rgb,lsb,xy  ./aee487a2-49cd-4f1f-ada6-b2d398342d99.SteinsGate  > keepass.kdbx
```
```
$ file keepass.kdbx 
keepass.kdbx: Keepass password database 2.x KDBX
```
```
pix and password
weak password!
lower casee letters and number
len(password) == 10
hitb + number
Crack Master password by john the ripper, I found Master Password is hitb180408
```
```
Open keepass.kdbx with KeePass
Group: flag, Title: flag, User Name: myname, Password: ********, URL: http://keepass.info/, Creation Time: 4/8/2018 3:49:14 PM, Last Modification Time: 4/8/2018 3:50:45 PM

HITB{p1x_aNd_k33pass}
```