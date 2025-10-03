#   Player Pipe Example
Play softswitch audio in the webbrowser.

1. `bun run examples/player_pipe/server.js`
2. `firefox http://localhost:3000`
3. `./bin/media_dumper -m ws://localhost:3002`
4. `fs_cli -x 'originate user/1001 &playback(/etc/freeswitch/audios/stones-karaoke.wav)'`
