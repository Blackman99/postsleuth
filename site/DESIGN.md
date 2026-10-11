# postsleuth design brief

**Reference object:** a metro / rapid-transit network diagram (octilinear schematic in the Harry Beck tradition) plus the line-status board you see at station entrances. Postfix really is a network of stations: `smtpd` and `pickup` feed `cleanup`, mail rides through `incoming` to `active`, leaves on the `smtp`/`local` lines, loops through `deferred` when a destination refuses it, and is sent back on the `bounce` line. postsleuth is the network map and the status board for that system.

**Metaphor:** message = train, queue = station, deferred = a loop line trains circle on, destination domain = terminus, delay reason = service notice ("Severe delays: 421 4.7.28 rate limited"), qshape = a platform matrix of waiting trains by age, `--allow-mutations` = a locked set of points to the siding.

- **Base tone:** light, cool lilac mist `#ece7f3` (no other project uses a violet-tinted light base). Map panel areas use `#f7f4fb`.
- **Palette:** ink aubergine `#241a33` (text, station rings) · jade delivery line `#00876f` · mulberry deferred loop `#a3245e` · slate hold siding `#7d7891` · lilac mist `#ece7f3` / `#f7f4fb`. Bounce line = ink dashed. White `#ffffff` only as line casing and station fill. No red ink, no beige, no gradients, no glow.
- **Type:** Jost 400/500/700 (geometric, metro-signage lineage) for everything; DM Mono 400/500 only for commands and SMTP replies. Self-hosted woff2 (OFL).
- **Texture:** transit-diagram line work: thick lines (10px) with white casing, round caps, 45°/90° angles only, station ticks and white interchange capsules with ink outlines. No paper, no grain, no shadows.
- **Rendering:** octilinear transit schematic in inline SVG; trains are small capsules moved along SVG paths by `app.js` (`getPointAtLength`, requestAnimationFrame), no libraries.
- **Layout:** the first screen *is* the network map, full width. The `h1` lives in the map's legend cartouche (boxed key at the lower right, with the line colour key) rather than as a free-standing headline. Below: sections are **strip maps** (the horizontal line diagram above a train door): a single coloured line with stations, text hanging below each station. The "status board" section is a TfL-style line-status list (coloured line bar · destination · status · notice). qshape is a platform matrix of dots. The safety section is a points diagram with a locked siding.
- **Motion:** trains depart smtpd/pickup and run to active; most continue to their terminus; trains for gmail.com divert onto the mulberry deferred loop and circle while the loop counter rises; one train runs back along the dashed bounce line to the sender. Strip maps: a train runs along the strip when it scrolls into view and each station lights as it passes (LED line-indicator behaviour). qshape dots fill column by column. Points diagram: toggling `--allow-mutations` swings the switch blade and the siding buffer unlocks. `prefers-reduced-motion`: static map with trains parked at stations, everything in final state.
- **Logo:** a jade line entering from the left, a white interchange capsule, and a mulberry loop leaving and returning to it (the deferred loop). No tile, no rounded square, transparent background.
- **OG / social preview:** the same map crop, with the legend cartouche carrying the name and the one-line pain.

## Banned-list self check
No dark base + cyan/purple gradient · no gradient text · no glow · no glassmorphism · no left-copy/right-card hero (the hero is a full-width map; text is inside the map key) · no three feature cards · no Inter, no Inter+mono default pairing (Jost + DM Mono) · no paper/print/stamp/typewriter · no line-by-line printing animation · no hard-shadow paper stacks · no rounded-square app-icon logo.

## Differences from every registered project
- toolsmoke (warm paper report): ours is lilac, diagrammatic, no paper/ink/stamps.
- agentckpt (Game Boy pixels): vector, smooth curves at 45°, no pixels, no steps().
- certfan (near-black generative fan): light base, schematic not generative, no fan of thin lines.
- linelore (Swiss poster, white + orange): not type-as-image; map-led, lilac base, no orange.
- runbill (isometric block city, concrete grey): flat 2D schematic, no 3D, no isometric.
- actnode (highway guide signs, saturated green): metro diagram rather than road signage; light lilac base; jade is a thin line colour not a full sign face; Jost not Overpass; no perspective road.
- drainready (container port side elevation): no illustration of physical objects; abstract network diagram; no stencil type.
