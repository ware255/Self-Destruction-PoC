#  Self-Destruction-PoC
Code Injectionを使った自己破壊コード

## 仕組み
デバック権限の取得<br>
↓<br>
インジェクトするプロセスIDの取得<br>
↓<br>
現在のPEファイルのパスを取得<br>
↓<br>
新しいメモリブロックを割り当てて、現在のPEイメージを新しいメモリブロックにコピーする。<br>
↓<br>
インジェクトするプロセスを開く<br>
↓<br>
インジェクトするプロセスに新しいメモリブロックを割り当てる。ここにPEを注入します。<br>
↓<br>
最初に割り当てたメモリブロックを再配置し、インジェクトするプロセス内で正しいアドレスを持つようにする。<br>
↓<br>
再配置されたメモリブロックをインジェクトするプロセスに書き込む。<br>
↓<br>
インジェクトするプロセス内でインジェクトされたPEを起動<br>
↓<br>
自己破壊GG

## 参考資料
[PE Injection: Executing PEs inside Remote Processes](<https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes>)
