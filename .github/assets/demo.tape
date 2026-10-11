# Re-record: vhs .github/assets/demo.tape  (from the repo root; needs vhs, ttyd, ffmpeg, DM Mono)
# Demo data: testdata/gen.py writes a queue snapshot (postqueue -j) and a mail log, so the
# recording does not need a live mail server. On a real host you just run `postsleuth doctor`.
Output site/demo.gif

Set Shell "bash"
Set FontSize 14
Set FontFamily "DM Mono"
Set Width 1280
Set Height 860
Set Padding 26
Set Margin 0
Set BorderRadius 0
Set Theme {"name": "postsleuth", "black": "#241a33", "red": "#a3245e", "green": "#00876f", "yellow": "#8a6a00", "blue": "#3d4f9e", "magenta": "#a3245e", "cyan": "#00876f", "white": "#f7f4fb", "brightBlack": "#7d7891", "brightRed": "#a3245e", "brightGreen": "#00876f", "brightYellow": "#8a6a00", "brightBlue": "#3d4f9e", "brightMagenta": "#a3245e", "brightCyan": "#00876f", "brightWhite": "#ffffff", "background": "#f7f4fb", "foreground": "#241a33", "selection": "#ece7f3", "cursor": "#00876f"}
Set TypingSpeed 35ms
Set Framerate 20

Hide
Type "source .github/assets/demo-rc.sh && clear"
Enter
Sleep 4s
Show

Type "postsleuth doctor --queue-file queue.json --log mail.log --no-dns"
Sleep 400ms
Enter
Sleep 9s

Hide
Type "clear"
Enter
Show
Type "postsleuth trace old.user3@yahoo.com --log mail.log --since all --limit 1"
Sleep 400ms
Enter
Sleep 5s
