    window.crypto = window.crypto || window.msCrypto; //for IE11
    if (window.crypto.webkitSubtle) {
        window.crypto.subtle = window.crypto.webkitSubtle; //for Safari
    }
    /*
    ArrayBuffer.prototype.prepend =  function (b) { // a, b TypedArray of same type
        var ab§ = new (this.constructor)(b.length + this.length);
        ab.set(b, 0);
        ab.set(this, b.length);
        return ab;
    }*/
    function arrToBase64(arr) {
        var binstr = Array.prototype.map.call(arr, function(ch) {
            return String.fromCharCode(ch);
        }).join('');
        return btoa(binstr);
    }
    /*
    function ab2str(buf) {
        return String.fromCharCode.apply(null, new Uint16Array(buf));
    }*/
    /*
    function str2ab(str) {
        var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
        var bufView = new Uint16Array(buf);
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }*/
    /*
    function Uint8Array2ab(uint8Array) {
        if (uint8Array instanceof Uint8Array) {
            return uint8Array.buffer;
        }
        throw new Error('Uint8Array2ArrayBuffer : Invalid argument, should be instance of Uint8Array')
    }*/
    /*
    function ab2Uint8Array(arrayBuffer) {
        if (arrayBuffer instanceof ArrayBuffer) {
            return new Uint8Array(data, 0);
        }
    }*/
    async function digestPassord(password) {
        const pwUtf8 = new TextEncoder().encode(password); // encode password as UTF-8
        const pwHash = await window.crypto.subtle.digest('SHA-256', pwUtf8); // hash the password
        return pwHash;
    }
    /**
     * Encrypts plaintext using AES-GCM with supplied password, for decryption with aesGcmDecrypt().

     * @param   {arrayBuffer} plaintext - Plaintext to be encrypted.
     * @param   {String}      password - Password to use to encrypt plaintext.
     * @returns {String}      Encrypted cipherText
     *
     * @example
     *   const ciphertext = await aesGcmEncrypt('my secret text', 'pw');
     *   aesGcmEncrypt('my secret text', 'pw').then(function(ciphertext) { console.log(ciphertext); });
     */
    async function aesGcmEncrypt(arrayBuffer, password) {
        // hash the password
        const pwHash = await digestPassord(password);
        // get 96-bit random iv
        const iv = crypto.getRandomValues(new Uint8Array(12));
        // specify algorithm to use
        const alg = { name: 'AES-GCM', iv: iv };
        // generate key from pw
        const key = await window.crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);
        // encode plaintext as UTF-8
        // const ptUint8 = new TextEncoder().encode(plaintext);    
        // encrypt plaintext using key
        const ctBuffer = await window.crypto.subtle.encrypt(alg, key, arrayBuffer);
        // ciphertext as byte array
        //const ctArray = Array.from(new Uint8Array(ctBuffer));
        // ciphertext as string                           
        //const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('');
        // encode ciphertext as base64   
        // 
        const ctBase64 = arrToBase64(new Uint8Array(ctBuffer));
        // iv as hex string
        const ivHex = Array.from(iv).map(b => ('00' + b.toString(16)).slice(-2)).join('');
        //console.log('iv:' + iv);
        //console.log('ivHex:' + ivHex);
        //console.log('ctBase64:' + ctBase64);
        //console.log('ctBase64:' + ctBase64);
        // return iv+ciphertext
        return ivHex + ctBase64;
    }
    /**
     * Decrypts ciphertext encrypted with aesGcmEncrypt() using supplied password.
     *                                                                      (c) Chris Veness MIT Licence
     *
     * @param   {String} ciphertext - Ciphertext to be decrypted.
     * @param   {String} password - Password to use to decrypt ciphertext.
     * @returns {String} Decrypted plaintext.
     *
     * @example
     *   const plaintext = await aesGcmDecrypt(ciphertext, 'pw');
     *   aesGcmDecrypt(ciphertext, 'pw').then(function(plaintext) { console.log(plaintext); });
     */
    async function aesGcmDecrypt(ciphertext, password) {
        // hash the password
        const pwHash = await digestPassord(password);
        // get iv from ciphertext                    
        const iv = ciphertext.slice(0, 24).match(/.{2}/g).map(byte => parseInt(byte, 16));
        // console.log('iv:' + iv);
        // specify algorithm to use
        const alg = { name: 'AES-GCM', iv: new Uint8Array(iv) };
        // use pw to generate key
        const key = await window.crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);
        // decode base64 ciphertext
        const ctStr = atob(ciphertext.slice(24));
        // ciphertext as Uint8Array                         
        const ctUint8 = new Uint8Array(ctStr.match(/[\s\S]/g).map(ch => ch.charCodeAt(0)));
        // note: why doesn't ctUint8 = new TextEncoder().encode(ctStr) work?
        // decrypt ciphertext using key
        const plainBuffer = await window.crypto.subtle.decrypt(alg, key, ctUint8);
        // decode password from UTF-8               
        // const plaintext = new TextDecoder().decode(plainBuffer);                            
        return plainBuffer; //arrayBuffer; new Uint8Array(plainBuffer); // ArrayBuffer => Uint8Array):
        // return the plaintext
    }
    /*
    async function run() {
        const plaintext = "This my secret message";
        var data = new Uint8Array([0x03, 0x04, 0x05]);
        var data = Uint8Array2ab(data);
        console.log(data);
        const password = 'toto';
        console.log('password', password);
        let ciphertext = await aesGcmEncrypt(data, password);
        console.log("ciphertext", ciphertext);
        // Decrypt
        let decryptedBuffer = await aesGcmDecrypt(ciphertext, password);
        console.log('decryptedText', decryptedBuffer);
        console.log((ab2Uint8Array(data).toString() == ab2Uint8Array(decryptedBuffer).toString()) ? "SUCCESS :-)" : "FAILED :-(");
    }*/
    //run();
    /* http://javascriptobfuscator.com/Javascript-Obfuscator.aspx
       http://beautifytools.com/html-minifier.php */
    /*
    function arrayBufferToBase64(buffer) {
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
        return base64String;
    }*/
    /*
    function base64ToArrayBuffer(base64) {
        var rawData = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        return rawData;
    }*/
    function exportArrayBuffer(arrayBuffer, filename) {
        var blob = new Blob([arrayBuffer], { type: "application/octet-stream" });
        saveAs(blob, filename);
    }

    function setFileContentSet(encrypted) {
        $('#password').val('');
        $('#progress').text('');
        $('#enc-button').css('display', encrypted ? 'none' : 'inline-block');
        $('#dec-button').css('display', encrypted ? 'inline-block' : 'none');
        $('#new-button').css('display', encrypted ? 'inline-block' : 'none');
    }

    function b2Mb(fileLength) {
        return Number(fileLength / (1024 * 1024)).toFixed(0) + 'Mb';
    }
    var separator = "||",
        password = undefined,
        errorMsg1 = "Error: Wrong encryption password !",
        errorMsg2 = "Error : Encryption password cannot be empty !",
        errorMsg3 = "Error : Wrong decrypted bytes length!",
        errorMsg4 = "Error : The maximum allowed file size is 50Mb!";
    /*    
    // Code goes here
    var keySize = 512,
    ivSize = 128,
    iterations = 100;


    function encrypt(msg, pass) {
        var salt = CryptoJS.lib.WordArray.random(128 / 8);
        var key = CryptoJS.PBKDF2(pass, salt, {
            keySize: keySize / 32,
            iterations: iterations
        });
        var iv = CryptoJS.lib.WordArray.random(128 / 8);
        var encrypted = CryptoJS.AES.encrypt(msg, key, {
            iv: iv,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });
        // salt, iv will be hex 32 in length
        // append them to the ciphertext for use  in decryption
        var transitmessage = salt.toString() + iv.toString() + encrypted.toString();
        return transitmessage;
    }

    function decrypt(transitmessage, pass) {
        try {
            var salt = CryptoJS.enc.Hex.parse(transitmessage.substr(0, 32));
            var iv = CryptoJS.enc.Hex.parse(transitmessage.substr(32, 32))
            var encrypted = transitmessage.substring(64);
            var key = CryptoJS.PBKDF2(pass, salt, {
                keySize: keySize / 32,
                iterations: iterations
            });
            var decrypted = CryptoJS.AES.decrypt(encrypted, key, {
                iv: iv,
                padding: CryptoJS.pad.Pkcs7,
                mode: CryptoJS.mode.CBC
            })
            return decrypted.toString(CryptoJS.enc.Utf8);
        } catch (err) {
            return false;
        }
    }

    */
    $(function() { // JQuery
        $('#dec-button').click(function() {
            var password = $('#password').val().trim();
            if (password == '') {
                alert(errorMsg2);
                return;
            }
            var data = $('#data').text();
            var sdata = data.split(separator);
            if (sdata && sdata.length == 3) {
                var filename = atob(sdata[0]);
                var fileLength = parseInt(atob(sdata[1]));
                var encrypted = sdata[2];
                $('#status').text('Decrypting in progress...');
                aesGcmDecrypt(encrypted, password).then(function(decrypted) {
                    if (decrypted.byteLength != fileLength) {
                        alert(errorMsg2);
                        return;
                    }
                    exportArrayBuffer(decrypted, filename);
                    $('#password').val('');
                    $('#new-button').css('display', 'inline-block');
                    $('#enc-input').val(null);
                    $('#status').text('Decrypted file:' + filename + ' size:' + b2Mb(fileLength));
                }).catch(function(err) {
                    console.error(err);
                    alert(errorMsg1);
                    $('#password').val('');
                    $('#status').text('');
                    return;
                });
            }
            /*
            var decrypted = aesGcmDecrypt(encrypted, password);
            if (!decrypted) {
                alert(errorMsg1);
                $('#password').val('');
                return;
            }
            var sdata = decrypted.split(separator);
            if (sdata && sdata.length == 2) {
                var filename = sdata[0];
                var rawData = base64ToArrayBuffer(sdata[1]);
                var fileLength = rawData.byteLength;
                exportArrayBuffer(rawData, filename);
                $('#password').val('');
                $('#status').text('Decrypted file:' + filename + ' size:' + fileLength);
                $('#new-button').css('display', 'inline-block');
                $('#enc-input').val(null);
            } else {
                alert(errorMsg1);
                $('#password').val('');
            }*/
        });
        $('#enc-button').click(function() {
            password = $('#password').val().trim();
            if (password != '') {
                setTimeout(function() {
                    $('#enc-input').trigger('click');
                }, 500);
            } else {
                alert(errorMsg2);
            }
        });
        $('#enc-input').change(function() {
            var file = this.files[0];
            var fileLength = file.size;
            if (fileLength > 50 * 1024 * 1024) { // 50MB
                alert(errorMsg4 + ' (Your file size is ' + b2Mb(fileLength) + ')');
                $('#enc-input').val(null);
                return;
            }
            $('#status').text('Uploading file ' + file.name + ' ...');
            var reader = new FileReader();
            reader.onloadend = function(evt) {
                if (evt.target.readyState == FileReader.DONE) {
                    var rawData = evt.target.result;
                    var filename = file.name;
                    $('#progress').text('');
                    $('#status').text('Encryption in progress...');
                    var encrypted = aesGcmEncrypt(rawData, password).then(function(encrypted) {
                        var data = [btoa(filename), btoa(fileLength), encrypted].join(separator);
                        $('#data').text(data);
                        $('#status').text('Encrypted file:' + filename + ' size:' + b2Mb(fileLength));
                        setFileContentSet(true);
                        var html = document.documentElement.innerHTML;
                        var ms = new Date().getTime();
                        exportArrayBuffer(html, 'Cryptojs_transfer_' + ms + '.html');
                    }).catch(function(err) {
                        console.error(err);
                        $('#status').text('Encryption failed: '+err);
                    });
                }
            };
            reader.onprogress = function(data) {
                if (data.lengthComputable) {
                    var progress = parseInt(((data.loaded / data.total) * 100), 10);
                    $('#progress').text(progress + '%');
                }
            }
            reader.readAsArrayBuffer(file);
        });
        $('#new-button').click(function() {
            setFileContentSet(false);
            $('#data').text('');
            $('#status').text('');
        });
    });