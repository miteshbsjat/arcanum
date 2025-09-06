# arcanum

## Meaning of `arcanum`

`arcanum` means `secret` in Latin/Sanskrit/Hindi. `arcanum` stores secrets in `etcd` after encryption. This is 3-tier scalable architecture to keep configurations and secrets in etcd.

"Arcanum" का हिंदी में अर्थ " रहस्य " या " भेद " है। इसका मतलब है कोई गुप्त, छिपा हुआ या रहस्यमय बात जो हर किसी को पता नहीं होती है। इसे "गुह्य ज्ञान" या "गुप्त रहस्य" भी कहा जा सकता है। [1, 2, 3, 4]  
उदाहरण के लिए, "The ancient book was filled with arcanum" का हिंदी में अर्थ होगा "प्राचीन पुस्तक रहस्यों से भरी हुई थी". [3, 5]  
संक्षेप में, "Arcanum" का उपयोग किसी ऐसी चीज का वर्णन करने के लिए किया जाता है जो रहस्यमय, गुप्त या समझने में मुश्किल हो, और जिसे केवल कुछ ही लोग जानते हों। [3, 4]  

## Building the Code

Compile the code

```bash
go build -o arcanum arcanum.go
```

## Running the arcanum

### Start the etcd server

Please refer this [`etcd` quick start guide](https://etcd.io/docs/v3.5/quickstart/)

### Start the Middleware `arcanum` API

```bash
./arcanum
```

### Using UI Frontend in Web Browser

```bash
open index.html
```

It will open `index.html` in web browser with the following UI:-

![arcanum Frontend](images/arcanum_00.png)

---
## References
[1] https://www.shabdkosh.com/dictionary/english-hindi/arcana/arcana-meaning-in-hindi

[2] https://translate.google.com/translate?u=https://www.dictionary.com/browse/arcanum&hl=hi&sl=en&tl=hi&client=sge

[3] https://translate.google.com/translate?u=https://www.merriam-webster.com/dictionary/arcanum&hl=hi&sl=en&tl=hi&client=sge

[4] https://translate.google.com/translate?u=https://www.etymonline.com/word/arcana&hl=hi&sl=en&tl=hi&client=sge

[5] https://dict.hinkhoj.com/achanum-meaning-in-hindi.words

