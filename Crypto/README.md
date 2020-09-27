# Crypto

## Pipe Rhyme

> So special

In this challenge we just needed to factorise the module n and calculate the private key d for the decryption. I used factordb and a simple python script.

```
from Crypto.Util.number import inverse, long_to_bytes

n = 0x3b7c97ceb5f01f8d2095578d561cad0f22bf0e9c94eb35a9c41028247a201a6db95f
e = 0x10001
c = 0x1B5358AD42B79E0471A9A8C84F5F8B947BA9CB996FA37B044F81E400F883A309B886
p = 31415926535897932384626433832795028841 # FactorDB
q = 56129192858827520816193436882886842322337671

f = (p - 1)*(q - 1)
d = inverse(e, f)
m_int = pow(c, d, n)
print(long_to_bytes(m_int).decode())
```

## haxXor

> you either know it or not take this and get your flag

In this challenge we were provided with the hex chain ```55 52 41 5c 2b 35 25 10 5a 46 57 07 1b 3e 0b 5f 49 4b 03 45 15```. Due to the challenge name it is probable that a XOR encryption was done. As we know that the flag format is darkCTF{...}, we can try to XOR flag plain chars with the provided chain to find the password partialy. In this case the password ```31 33 33 37 68 61 63 6b``` was cyclic. I used cyberchef to solve it.

```
https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'31%2033%2033%2037%2068%2061%2063%206b'%7D,'Standard',false)&input=NTUgNTIgNDEgNWMgMmIgMzUgMjUgMTAgNWEgNDYgNTcgMDcgMWIgM2UgMGIgNWYgNDkgNGIgMDMgNDUgMTU
```

## Easy RSA

> Just a easy and small E-RSA for you :) 

Sometimes when you use a small module such as e = 3 there is a risk that the encrypted text is smaller than the module so any modular operation is done. In that case decrypting the ciphertext is as easy as making the cube root.

```
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

e = 3
cipher = 70415348471515884675510268802189400768477829374583037309996882626710413688161405504039679028278362475978212535629814001515318823882546599246773409243791879010863589636128956717823438704956995941

m_int = iroot(cipher, e)[0]
print(long_to_bytes(m_int).decode())
```

## WEIRD ENCRYPTION

> I made this weird encryption I hope you can crack it.

This encryption method used an array of values and two operations, which where division and module. Both operations where done over the same plaintext char. It used that operations to get an element from the array of values for each operation. To decrypt it we must only get the corresponding index of each piece and do a simple calculation.

```
k = ['c', 'an', 'u', 'br', 'ea', 'k', 'th', 'is', 'we', 'ir', 'd', 'en', 'cr', 'yp', 'ti', 'on']

c = 'eawethkthcrthcrthonutiuckirthoniskisuucthththcrthanthisucthirisbruceaeathanisutheneabrkeaeathisenb>

i = 0
m = ""

while i < len(c):
    index_1 = None
    index_2 = None
    if (i+1) < len(c) and f"{c[i]}{c[i+1]}" in k:
        index_1 = k.index(f"{c[i]}{c[i+1]}")
        i += 2
    else:
        index_1 = k.index(f"{c[i]}")
        i += 1
    if (i+1) < len(c) and f"{c[i]}{c[i+1]}" in k:
        index_2 = k.index(f"{c[i]}{c[i+1]}")
        i += 2
    else:
        index_2 = k.index(f"{c[i]}")
        i += 1
    m += chr(index_1*16 + index_2)

print(m)
```

## Duplicacy Within (Pending)

> Looks like Mr. Jones has found a secret key. Can you retrieve it like him?
Format : darkCTF{hex value of key}
Check this: https://www.blockchain.com/btc/tx/83415dded4757181c6e1c55104e2742a6f8cff05a9a46fbf029ae47b0054d511
z1 = 0xc0e2d0a89a348de88fda08211c70d1d7e52ccef2eb9459911bf977d587784c6e
z2 = 0x17b0f41c8c337ac1e18c98759e83a8cccbc368dd9d89e5f03cb633c265fd0ddc

Solution comming soon.

```
# https://cocalc.com/projects/201e1ce5-a4d4-484b-aedd-f2d5a6abc496/files/Welcome%20to%20CoCalc.sagews?session=default&utm_medium=landingpage&utm_source=sagemath.org
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
z1 = 0xc0e2d0a89a348de88fda08211c70d1d7e52ccef2eb9459911bf977d587784c6e
z2 = 0x17b0f41c8c337ac1e18c98759e83a8cccbc368dd9d89e5f03cb633c265fd0ddc
r = 0xd47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1
s1 = 0x2f88bf73d0f94a1e917d1a6e65ba15a9dbf52d0999c91f2c2c6bb710e018f7e0
s2 = 0x3602aff824a32c19825425704546145d5fbc282ee912089923e824f46867647b

K = GF(p)

K((z1*s2 - z2*s1)/(r*(s1-s2)))
```

## E-AES

> Noob has sent a secret to his friend we were able to catch the a file and few messages. His message said that he used e-aes to encrypt. NOTE: E-AES isn't Extended AES for this challenge.

This was a cool challenge. The creator used a tool wich transformed a base64 aes encrypted text into emojis. To solve this challenge it was necesary to decode the hex value into unicode emojis and unemoji the provided ciphertext.

```
<!DOCTYPE html>
<html>
<body>

<script>
const emojis= ["🍎", "🍌", "🏎", "🚪", "👁", "👣", "😀", "🖐", "ℹ", "😂", "🥋", "✉", "🚹", "🌉", "👌", "🍍", "👑", "👉", "🎤", "🚰", "☂", "🐍", "💧", "✖", "☀", "🦓", "🏹", "🎈", "😎", "🎅", "🐘", "🌿", "🌏", "🌪", "☃", "🍵", "🍴", "🚨", "📮", "🕹", "📂", "🛩", "⌨", "🔄", "🔬", "🐅", "🙃", "🐎", "🌊", "🚫", "❓", "⏩", "😁", "😆", "💵", "🤣", "☺", "😊", "😇", "😡", "🎃", "😍", "✅", "🔪", "🗒"];

var message ="";

const unicode = ["1F643", "1F4B5", "1F33F", "1F3A4", "1F6AA", "1F30F", "1F40E", "1F94B", "1F6AB", "1F606", "1F52A", "1F52C", "1F6AA", "2753", "1F607", "1F606", "1F374", "1F40D", "1F34C", "1F3A4", "1F32A", "1F374", "2600", "1F6A8", "1F4EE", "1F60D", "2705", "1F3CE", "1F4A7", "1F6B9", "1F309", "1F52C", "2753", "1F6B9", "1F590", "1F923", "1F606", "1F923", "1F6A8", "2328", "1F60D", "1F6AA", "1F3F9", "1F579", "1F60D", "1F3A4", "1F388", "1F34C", "1F993", "2753", "1F600", "2753", "2603", "1F3CE", "2600", "2602", "2705", "1F601", "1F388", "1F4EE", "1F60A", "2716", "1F6AB", "2139"]
unicode.forEach((val) => {
	message += String.fromCodePoint(parseInt(val, 16))
});
console.log(message);



var unemojified = message.replace(new RegExp(emojis[0], "g"), "a");
      unemojified = unemojified.replace(new RegExp(emojis[1], "g"), "b");
      unemojified = unemojified.replace(new RegExp(emojis[2], "g"), "c");
      unemojified = unemojified.replace(new RegExp(emojis[3], "g"), "d");
      unemojified = unemojified.replace(new RegExp(emojis[4], "g"), "e");
      unemojified = unemojified.replace(new RegExp(emojis[5], "g"), "f");
      unemojified = unemojified.replace(new RegExp(emojis[6], "g"), "g");
      unemojified = unemojified.replace(new RegExp(emojis[7], "g"), "h");
      unemojified = unemojified.replace(new RegExp(emojis[8], "g"), "i");
      unemojified = unemojified.replace(new RegExp(emojis[9], "g"), "j");
      unemojified = unemojified.replace(new RegExp(emojis[10], "g"), "k");
      unemojified = unemojified.replace(new RegExp(emojis[11], "g"), "l");
      unemojified = unemojified.replace(new RegExp(emojis[12], "g"), "m");
      unemojified = unemojified.replace(new RegExp(emojis[13], "g"), "n");
      unemojified = unemojified.replace(new RegExp(emojis[14], "g"), "o");
      unemojified = unemojified.replace(new RegExp(emojis[15], "g"), "p");
      unemojified = unemojified.replace(new RegExp(emojis[16], "g"), "q");
      unemojified = unemojified.replace(new RegExp(emojis[17], "g"), "r");
      unemojified = unemojified.replace(new RegExp(emojis[18], "g"), "s");
      unemojified = unemojified.replace(new RegExp(emojis[19], "g"), "t");
      unemojified = unemojified.replace(new RegExp(emojis[20], "g"), "u");
      unemojified = unemojified.replace(new RegExp(emojis[21], "g"), "v");
      unemojified = unemojified.replace(new RegExp(emojis[22], "g"), "w");
      unemojified = unemojified.replace(new RegExp(emojis[23], "g"), "x");
      unemojified = unemojified.replace(new RegExp(emojis[24], "g"), "y");
      unemojified = unemojified.replace(new RegExp(emojis[25], "g"), "z");

 
      unemojified = unemojified.replace(new RegExp(emojis[26], "g"), "A");
      unemojified = unemojified.replace(new RegExp(emojis[27], "g"), "B");
      unemojified = unemojified.replace(new RegExp(emojis[28], "g"), "C");
      unemojified = unemojified.replace(new RegExp(emojis[29], "g"), "D");
      unemojified = unemojified.replace(new RegExp(emojis[30], "g"), "E");
      unemojified = unemojified.replace(new RegExp(emojis[31], "g"), "F");
      unemojified = unemojified.replace(new RegExp(emojis[32], "g"), "G");
      unemojified = unemojified.replace(new RegExp(emojis[33], "g"), "H");
      unemojified = unemojified.replace(new RegExp(emojis[34], "g"), "I");
      unemojified = unemojified.replace(new RegExp(emojis[35], "g"), "J");
      unemojified = unemojified.replace(new RegExp(emojis[36], "g"), "K");
      unemojified = unemojified.replace(new RegExp(emojis[37], "g"), "L");
      unemojified = unemojified.replace(new RegExp(emojis[38], "g"), "M");
      unemojified = unemojified.replace(new RegExp(emojis[39], "g"), "N");
      unemojified = unemojified.replace(new RegExp(emojis[40], "g"), "O");
      unemojified = unemojified.replace(new RegExp(emojis[41], "g"), "P");
      unemojified = unemojified.replace(new RegExp(emojis[42], "g"), "Q");
      unemojified = unemojified.replace(new RegExp(emojis[43], "g"), "R");
      unemojified = unemojified.replace(new RegExp(emojis[44], "g"), "S");
      unemojified = unemojified.replace(new RegExp(emojis[45], "g"), "T");
      unemojified = unemojified.replace(new RegExp(emojis[46], "g"), "U");
      unemojified = unemojified.replace(new RegExp(emojis[47], "g"), "V");
      unemojified = unemojified.replace(new RegExp(emojis[48], "g"), "W");
      unemojified = unemojified.replace(new RegExp(emojis[49], "g"), "X");
      unemojified = unemojified.replace(new RegExp(emojis[50], "g"), "Y");
      unemojified = unemojified.replace(new RegExp(emojis[51], "g"), "Z");

     
      unemojified = unemojified.replace(new RegExp(emojis[52], "g"), "0");
      unemojified = unemojified.replace(new RegExp(emojis[53], "g"), "1");
      unemojified = unemojified.replace(new RegExp(emojis[54], "g"), "2");
      unemojified = unemojified.replace(new RegExp(emojis[55], "g"), "3");
      unemojified = unemojified.replace(new RegExp(emojis[56], "g"), "4");
      unemojified = unemojified.replace(new RegExp(emojis[57], "g"), "5");
      unemojified = unemojified.replace(new RegExp(emojis[58], "g"), "6");
      unemojified = unemojified.replace(new RegExp(emojis[59], "g"), "7");
      unemojified = unemojified.replace(new RegExp(emojis[60], "g"), "8");
      unemojified = unemojified.replace(new RegExp(emojis[61], "g"), "9");

      
      unemojified = unemojified.replace(new RegExp(emojis[62], "g"), "+");
      unemojified = unemojified.replace(new RegExp(emojis[63], "g"), "/");
      unemojified = unemojified.replace(new RegExp(emojis[64], "g"), "=");


console.log(unemojified);


</script>

</body>
</html> 
```

With the base64 ciphertext just do bruteforce with CryptoJS.

```
const passwordList = require('rockyou')(75)
var CryptoJS = require("crypto-js");

const check = "darkCTF";
const encrypted = "U2FsdGVkX1/SdY61KvbsHKyLM9+cwmnSYmh313LQ9dAN9sBbzYgYIcyu+0BM5xXi";

passwordList.forEach(function test(word, passwordList){
    try{
        var msg = CryptoJS.AES.decrypt(encrypted, word).toString(CryptoJS.enc.Utf8);
        if(msg.includes(check)){
            console.log(msg);
        }
    } catch(error){
    }
});
```