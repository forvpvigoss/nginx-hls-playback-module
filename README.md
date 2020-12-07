# nginx-hls-playback-module
ngx playback module for hls live streaming

configuration:

server {
    listen       8081;
    server_name  localhost;

    location / {
        root   html;
        index  index.html index.htm;
    }

    //use hls_playback module
    location ~*\.m3u8$ {
        hls_playback;
        root html;
    }
}

eg:

curl http://127.0.0.1:8081/playback/play.m3u8?delay=XXX

a playlist with XXX seconds delay will be received.
