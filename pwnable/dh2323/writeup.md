# DreamHack 2323 (level 2)

docker

`docker run -p 1000:31337 fa081ae207b3`

## checksec
- Full RELRO
- No Canary
- NX Enabled
- No PIE

## Vulnerability
vulnerability in generate_character
- BoF
- can overwrite skill (int ()*)
- direct overwrite to Character struct is impossible
- use UAF (generate_monster doesn't always initialize the Monster struct)
- BoF to generate_character -> delete_character -> generate_monster

No PIE -> overwrite the function pointer value to the address of win()