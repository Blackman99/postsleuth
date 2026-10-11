`og.html` renders `site/social-preview.png` (1280x640) and `site/og-image.png` (1200x630):

    for s in 1280x640:../../site/social-preview.png 1200x630:../../site/og-image.png; do
      w=${s%%x*}; r=${s#*x}; h=${r%%:*}; out=${s#*:}
      sed "s/var(--w)/${w}px/g; s/var(--h)/${h}px/g" og.html > og_tmp.html
      google-chrome --headless=new --hide-scrollbars --window-size=$w,$h --screenshot=$out "file://$PWD/og_tmp.html"
    done; rm og_tmp.html

`site/logo-512.png`: render `site/logo.svg` at 512x512 with `--default-background-color=00000000`.
