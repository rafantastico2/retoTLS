# TLS Challenge: Cuando nos facilitan la factorización entera...
## 1. Información del reto
El reto nos presenta un archivo de captura de tráfico "tlsChallenge.pcapng" y la siguiente pista:
```bash
p = 0xc3821d8020da9e50ee5196be044cf3cf635e3d69bcf6bd76ab573b900991ff30c5d59c11cfce4a1fadb33262111f28544b388aa0bfb90efbdfb8e68ca49d8f8402485206211d274f87a75ae4f271ca446b75d3ca13181a116ee364e9fdc5718168e9ad7297bfc53d87c1c2d74cdfb1bb9f6ac511a91aba3c8fbd68be5a8b5d8c32e3bd1824e8ce91
```
Nota: Se ha supuesto una competición de captura la bandera en la que las *flags* tienen el siguiente formato: `ETIIT_CTF{FLAG}`
## 2. Resolución del reto
A continuación, se presenta un proceso de resolución de este reto detallando la cadena de razonamientos que podría dirigir al participante. Es importante aclarar que existen otras muchas formas de resolverlo, pero los autores consideran que la presente facilita, de forma más directa, la comprensión de los conceptos teóricos en los que se basa el reto.
### 2.1 Análisis Forense
El primer paso es explorar lo que contiene el archivo de captura de tráfico facilitado para el reto. Se puede utilizar el comando `strings` para ver qué cadenas de caracteres encontramos en la traza de tráfico `strings tlsChallenge.pcapng`. Se obtienen demasiadas cadenas de carecteres para analizarlas una a una así que filtramos con grep `strings tlsChallenge.pcapng | grep ETSIIT_CTF` obteniendo las siguientes cadenas sospechosas:
```
ETSIIT_CTF{d3mAsIAd0_F@cI1_N0?}
CTFETSIIT1
CTFETSIIT1
```
La primera cadena obtenida tiene el formato de una *flag* del reto pero parece demasiado fácil (como se indica en la misma *flag*). 

Para analizar en más detalle su procedencia abrimos la traza con Wireshark y realizamos la  búsqueda (*Ctrl+F*) de la cadena `ETSIIT_CTF{d3mAsIAd0_F@cI1_N0?}` en los bytes de los paquetes de la traza, en modo cadena (*String*) y diferenciando si se usan mayúsculas o minúsculas:

![](img/busquedaWireshark.png)

De esta forma, se puede descubrir que la cadena `ETSIIT_CTF{d3mAsIAd0_F@cI1_N0?}` se ha enviado por una conexión TCP entre las siguientes direcciones IP: 10.0.2.15 y 192.168.56.1. Direcciones locales y usadas comúnmente en Virtualbox. La dirección 10.0.2.15 suele estar asociada a una dirección NAT, mientras que la dirección 192.168.56.1 está asociada a una interfaz sólo anfitrión.

Siguiendo este mismo proceso, con las otras dos cadenas se llega a una comunicación TLS en la que se está enviando un certificado con la información `CTFETSIIT1` también entre esas mismas direcciones IP.

![](img/busquedaWireshark2.png)

Otro camino interesante para explorar la capturas de tráfico sería directamente desde Wireshark. Para esto, un primer paso es analizar la distribución de protocolos que se pueden encontrar. En la opción Statistics->Protocol Hierarchy se puede encontrar que la mayoría del tráfico es QUIC que viaja en capa de transporte UDP y que hay algo de TLS y HTTP sobre TCP.

![](img/protocolos.png)

Las direcciones IP que se pueden encontrar en la traza se consultan desde Statistics -> IPv4 Statistics->All Addresses. Aquí se pueden buscar direcciones IP privadas típicas y también llegaríamos a las mismas que se encontraron en el proceso anterior.

![](img/ips.png)

Por último, se realiza un filtrado para ver las comunicaciones capturadas entre las direccioens IP localizadas, utilizando para ello esta búsqueda: `ip.addr == 192.168.56.1 and ip.addr == 10.0.2.15`. En este filtrado se encuentran dos flujos diferentes:
- Uno en el que se envía la *flag* falsa en texto plano
- Otro que viaja cifrado utilizando TLS. Este segundo contiene es de especial interés al poseer texto cifrado que podría contener la *flag* verdadera.

![](img/filtradoWireshark.png)

Analizando el handshake de TLS se puede descubrir la suite criptográfica utilizada para el intercambio de clave y el cifrado. Esta selección en TLSv1.2 la realiza siempre el servidor así que consultando el Server Hello se descubre que se utiliza la suite criptográfica: `TLS_RSA_WITH_AES_256_GCM_SHA384`

![](img/cipherSuite.png)

Sabiendo que se utiliza RSA como intercambio de clave, en la siguiente parte de la resolución del reto el punto central es estudiar cómo se generan estas claves y cómo se podría llegar a la privada con lo que se dispone en el reto.
#### 2.2 Criptografía: generación de claves RSA
Revisar la teoría de RSA puede ayudar a resolver y comprender en mayor profundidad este reto. [Este](https://www.cryptool.org/en/cto/rsa-step-by-step) puede ser un buen recurso para ello.
1. Primero se extrae el módulo $n$ del certificado y el exponente $e$. Para esto se consulta el mensaje del *handshake* de TLS en el que se envía el certificado:

![](img/modulus.png)
2. Obtener  $q$ desde $n$ realizando una simple división y mostrando el resultado en hexadecimal.
```python
>>> n = 0xc137a8b795dc2c509c5e6f6c283af3052468f3b8e71dff0708ed1580d355c9a789c68e7ef987fdffa00552de96951f45e2daf9c12698312c71c2ae9c7370b94920174177451b4705e491917ea38c5f2f6e7644097884e93c8ea502550c97b7a25e5f403c9e1e127e16cb171ba826fe1fe783a6bc2d6e58042cc4a5ef1babf27862cefb94d2129bb893b309ed41a4b5b3ae8da629380403f636abba31ce57839b042285a299d908b72006f0e47705f3b114aec914629475dd317624ee590d27534875fc765e1a22fea54721ea2e32a15fb1abc539558f6b1825e6838fb901a581403be2e398347aae0b910ba50c3c7edb9df844c38c261dee6e70a854f0999745
>>> e = 0x10001
>>> p = 0xc3821d8020da9e50ee5196be044cf3cf635e3d69bcf6bd76ab573b900991ff30c5d59c11cfce4a1fadb33262111f28544b388aa0bfb90efbdfb8e68ca49d8f8402485206211d274f87a75ae4f271ca446b75d3ca13181a116ee364e9fdc5718168e9ad7297bfc53d87c1c2d74cdfb1bb9f6ac511a91aba3c8fbd68be5a8b5d8c32e3bd1824e8ce91
>>> q = n//p
>>> hex(q)
'0xfd0016ff0acd1a4322bf8c6a1e9b5d84abd87133a1e3f6fc34f86d49f7448ac961139a5c90d47d2a317285c3ee1a8d3ee2ac9eb5a6867096c5a00db0d34c1ab0dab87f72b5d51f18b3f00801171b68cb6d055e434887a64b0f5c29a79f1fdf55c208bd6ab9a67e4491fec6f3e4b611d24f959ba70345bf75'
```
3.  Obtener $d$ desde $p$, $q$ y $e$. Para esto, se pueden seguir varias aproximaciones. Se podría programar el cálculo siguiendo la teoría de RSA, o bien usar [este](https://github.com/sybrenstuvel/python-rsa) repositorio de Github o directamente [esta](https://www.dcode.fr/rsa-cipher) web que nos permite hallar $d$ teiendo el resto de valores de la clave RSA. En lo que sigue se muestra cómo se haría utilizando el repositorio de Github.
```python
>>> rsa.key.calculate_keys_custom_exponent(p,q,e)
(65537, 7919951013503635459035573036948764186999129498445536772390957633825219693149712189421017975916785525321336221017790513521963642446798020876375931900923576931742032276194574322083067303063688699141905639640444523549994066815008135956068198836267494938494798091815209028896682110264124213601010414877173449044983023720496129066596745731782357683494050369423429208936051989077555776314367724225783243460495649826613941409942656957263023788577668993683795904055033412187079058439074448787762217108489091662331987353820283481197635591658763896070867797958770975037692978233195845554283954164991251997618660716593719273473)
>>> d = 7919951013503635459035573036948764186999129498445536772390957633825219693149712189421017975916785525321336221017790513521963642446798020876375931900923576931742032276194574322083067303063688699141905639640444523549994066815008135956068198836267494938494798091815209028896682110264124213601010414877173449044983023720496129066596745731782357683494050369423429208936051989077555776314367724225783243460495649826613941409942656957263023788577668993683795904055033412187079058439074448787762217108489091662331987353820283481197635591658763896070867797958770975037692978233195845554283954164991251997618660716593719273473
>>> hex(d)
'0x3ebcf3eba89d7546377ff26e0c221806f36ba0b7c953d41b54aaa6f0cdae6d6c19307fd47af1cd67d36de71a9f8a8c3d050c554c825ba89be5d4711e1bddde4c003f8ce24d6e2e019bd628881652de1568a8be2ed513532876a8ddb8fffdc382d561d859d67dad4383e32dfdacfbfc481fc47fbf5a8119d301bab8d2505ee814679ecfbf6fd15e53e756fa19a9f97a1a48e84ffcb807db070cefd1d66dbebb78cc44ef26c0d47896fb1d0c58620576998cea7a949a49d224d7f29c204f57175b2bb4540ff968fa3bd0c51d56f02b394b2ab6d4f593cb1af8e95e516c4b132cffb0ea29b746b367a79715401413f413440e52f4044a13771b0463a953d95fe801'
```
4. Una vez se tiene $d$ se puede formar y almacenar la clave privada completa que se utilizó en el el servidor Web como base del intercambio de clave de TLS. 
```python
>>> privKey = rsa.PrivateKey(n, e, d, p, q)
>>> privKey
PrivateKey(24391439359585890840169847280193193539631670579869602605835817220300912736369957131488968754119284444219192289325325981423352031721607231869128263580396074312762103819782134273795017943650609317465369826368224282889847798724397942018460599019382651117675450307485589949567756365619356606523651904241946343339334582845006429146764510855628779938610428665137175385604792229658923350912553442177544957776662701455126156806474304090191304536457593382607280769119936783770346004562234926689511707929638489040324664341820404617774784276983801016580838959443629968969840470859079740594452213951941874414515095004397308581701, 65537, 7919951013503635459035573036948764186999129498445536772390957633825219693149712189421017975916785525321336221017790513521963642446798020876375931900923576931742032276194574322083067303063688699141905639640444523549994066815008135956068198836267494938494798091815209028896682110264124213601010414877173449044983023720496129066596745731782357683494050369423429208936051989077555776314367724225783243460495649826613941409942656957263023788577668993683795904055033412187079058439074448787762217108489091662331987353820283481197635591658763896070867797958770975037692978233195845554283954164991251997618660716593719273473, 2532564025531102265037006455431485037847411449963640251652918790356910031140769147393503843725387430641438578753463053534153164127657344111219409616759024036301736419544537401289871429248405800043831251473744784841980340046895310035453286011807874401657054964521697167723615692475304866472447031922648892564638078679358879878801, 9631124470573168952360482820524749856784397670693336495684924008608426642066969223285122463431061999265748771577578141462737386978842769016912533353226581993256940354434606441095665685558557058484588313552787072781093070353137059185826060598579567256821558715804650920932741541983796182901)
>>> privkeydata = rsa.PublicKey.save_pkcs1(privKey)
>>> privkeydata
b'-----BEGIN RSA PRIVATE KEY-----\\nMIIEqQIBAAKCAQEAwTeot5XcLFCcXm9sKDrzBSRo87jnHf8HCO0VgNNVyaeJxo5+\\n+Yf9/6AFUt6WlR9F4tr5wSaYMSxxwq6cc3C5SSAXQXdFG0cF5JGRfqOMXy9udkQJ\\neITpPI6lAlUMl7eiXl9APJ4eEn4WyxcbqCb+H+eDprwtblgELMSl7xur8nhizvuU\\n0hKbuJOzCe1BpLWzro2mKTgEA/Y2q7oxzleDmwQihaKZ2Qi3IAbw5HcF87EUrskU\\nYpR13TF2JO5ZDSdTSHX8dl4aIv6lRyHqLjKhX7GrxTlVj2sYJeaDj7kBpYFAO+Lj\\nmDR6rguRC6UMPH7bnfhEw4wmHe5ucKhU8JmXRQIDAQABAoIBAD688+uonXVGN3/y\\nbgwiGAbza6C3yVPUG1SqpvDNrm1sGTB/1HrxzWfTbecan4qMPQUMVUyCW6ib5dRx\\nHhvd3kwAP4ziTW4uAZvWKIgWUt4VaKi+LtUTUyh2qN24//3DgtVh2FnWfa1Dg+Mt\\n/az7/EgfxH+/WoEZ0wG6uNJQXugUZ57Pv2/RXlPnVvoZqfl6GkjoT/y4B9sHDO/R\\n1m2+u3jMRO8mwNR4lvsdDFhiBXaZjOp6lJpJ0iTX8pwgT1cXWyu0VA/5aPo70MUd\\nVvArOUsqttT1k8sa+OleUWxLEyz/sOopt0azZ6eXFUAUE/QTRA5S9ARKE3cbBGOp\\nU9lf6AECgYkAw4IdgCDanlDuUZa+BEzzz2NePWm89r12q1c7kAmR/zDF1ZwRz85K\\nH62zMmIRHyhUSziKoL+5DvvfuOaMpJ2PhAJIUgYhHSdPh6da5PJxykRrddPKExga\\nEW7jZOn9xXGBaOmtcpe/xT2HwcLXTN+xu59qxRGpGro8j71ovlqLXYwy470YJOjO\\nkQJ5AP0AFv8KzRpDIr+Mah6bXYSr2HEzoeP2/DT4bUn3RIrJYROaXJDUfSoxcoXD\\n7hqNPuKsnrWmhnCWxaANsNNMGrDauH9ytdUfGLPwCAEXG2jLbQVeQ0iHpksPXCmn\\nnx/fVcIIvWq5pn5Ekf7G8+S2EdJPlZunA0W/dQKBiFH9UxnUrVoPXqJgsTdkfirO\\n5Uqj+VcQhZ+9aYEyQkPe1FiMpvua64L1eVz7u2pxo0gYYiqfvKAICP6l0P2IBhO6\\nUVH0uBZd0gB1sqyo8Ad/QgGb2/a9+NCuzDYZ2w7eVwMEXHTeJtI0x6X+bAQVG5gv\\ndrtGeMB4scUmDbMmjaOhlAXl2yY/a8ECeQC6Rt+nps8+n+GswPi9Uk03ysMRDiAL\\nVaV6ZtMo24s22HDGWyf+ZsVFVKTqgkkEeaysfsZYHqTrrscRQiNIX8djIZcoF1Bz\\n+3JXwcpS6y1+KhE6G55Uf7PbnhKQhN8vO2PL+l1kgA5q95e6y8d1ROy4OWqA8SYC\\nq6UCgYgx1W8iyNJqoUC44wFCyxJS8dSo1oLUUIFTGVTf6kcSsH2PQT8VO2nIMBWC\\nTCtXvX0TxKOYOlCaLpEG3/DL0HrarO1VLSUTooHCXsu5HGWKsTnE99LRX87vTsw3\\nZ3wOI+1v/p6EZ+1uHOvtUu1ltsxqa5HPbajULEKEfChje7Z2GXrBO9rJiUpV\\n-----END RSA PRIVATE KEY-----\\n'
>>> of = open('private.pem', mode='wb')
>>> of.write(privkeydata)
>>> of.close()
```
5.  Para descifrar el tráfico es necesario cargar esta clave privada en Wireshark como se indica en la figura. Así, Wireshark podrá ver en el mensaje ClientKeyExchange el secreto premaestro compartido que viaja cifrado con la clave pública del servidor. A partir de este, momento podrá descifrar el resto de la comunicación con `AES_256_GCM` y la clave recuperada.

![](img/keylist.png)

6. En la siguiente imagen, habiendo descifrado el tráfico, pueden verse los mensajes `HTTP GET` y `Response` asociados a la comunicación TLS.

![](img/descifrado.png)

7. Si se exporta el código HTML que el servidor web está enviando al cliente como respuesta a su petición ``GET`` y se renderiza en un navegador web se puede ver la página web consultada y en ella el *flag* del reto.

![](img/web.png)
