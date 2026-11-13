#!/usr/bin/env bash
# Live demos for the presentation, on Linux or macOS.
#
#   demo/commands.sh setup      once, the day before: keys, signatures, certificates
#   demo/commands.sh 1 ... 9    one demo
#   demo/commands.sh all        every demo in order
#   demo/commands.sh tsa        the time authority as a service, in a second terminal (demo 8)
#
# Run from a real terminal (the program reads passwords from the console). Every
# password prompt takes the same long demo password. Needs `mvn package` first.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/demo/work"
JAR="$ROOT/target/rsa-pss-signer.jar"
CP="$JAR:$ROOT/target/lib/*"

signer() { java -jar "$JAR" "$@"; }
tools() { java -cp "$CP" "$ROOT/demo/DemoTools.java" "$@"; }
say() { printf '\n\033[1;37m# %s\033[0m\n' "$*"; }
step() {
    printf '\n\033[1;31m$ %s\033[0m\n' "$*"
    "$@"
    printf '\033[2m(exit code %s)\033[0m\n' "$?"
}
pause() {
    if [ -z "${DEMO_NO_PAUSE:-}" ]; then read -r -p "-- Enter to continue --" _; fi
}
# Each demo gets its own local state, as if it ran on its own machine
state() { export RSA_PSS_SIGNER_HOME="$WORK/state-$1"; }

setup() {
    if [ ! -f "$JAR" ]; then (cd "$ROOT" && mvn -q -DskipTests package) || exit 1; fi
    if [ -e "$WORK" ]; then echo "$WORK already exists; delete it to prepare again."; exit 1; fi
    mkdir -p "$WORK/mallory" "$WORK/replay" && cd "$WORK" || exit 1
    state setup

    printf 'Ana Perez sells her car to Bob Diaz for 20,000,000 COP, paid on delivery.\n' > contract.txt
    cp contract.txt contract_tampered.txt
    printf '3' | dd of=contract_tampered.txt bs=1 seek=40 conv=notrunc 2> /dev/null

    say "Keys for Ana and Mallory"
    signer keygen --out ana || exit 1
    signer keygen --out mallory || exit 1
    say "Keys for the brute-force demo: 1,000 and 600,000 PBKDF2 iterations"
    tools keys weak 1000 || exit 1
    tools keys strong 600000 || exit 1

    say "Ana signs the contract"
    signer sign contract.txt --key ana.key --signer "Ana Perez" || exit 1
    signer verify contract.txt --sig contract.txt.sig --pub ana.pub | sed -n 's/^Key fingerprint: //p' > ana.fingerprint

    say "Mallory edits the contract and signs it as Ana, with her own key"
    sed 's/20,000,000/2,000,000/' contract.txt > mallory/contract.txt
    signer sign mallory/contract.txt --key mallory.key --signer "Ana Perez" || exit 1

    say "Two versions of a document, the second chained to the first"
    printf 'Price: 20,000,000 COP.\n' > replay/v1.txt
    printf 'Price: 25,000,000 COP.\n' > replay/v2.txt
    cp replay/v1.txt replay/contract.txt
    signer sign replay/contract.txt --key ana.key --signer "Ana Perez" --out replay/v1.sig || exit 1
    cp replay/v2.txt replay/contract.txt
    signer sign replay/contract.txt --key ana.key --signer "Ana Perez" --out replay/v2.sig --previous replay/v1.sig || exit 1

    say "Certificate authority, certificates for Ana and Mallory, and a time authority"
    signer ca init --out ca --name "ICESI Demo CA" || exit 1
    signer ca issue --ca ca --pub ana.pub --name "Ana Perez" --out ana.crt || exit 1
    signer ca issue --ca ca --pub mallory.pub --name "Mallory" --out mallory.crt || exit 1
    signer ca crl --ca ca || exit 1
    cp ca.crl ca-empty.crl
    signer keygen --out tsa || exit 1
    signer tsa stamp contract.txt.sig --key tsa.key || exit 1

    printf '%%PDF-1.7\n%% demo\n' > invoice.pdf
    rm -rf "$WORK/state-setup"
    say "Ready in $WORK"
}

demo1() {
    say "Demo 1: public key substitution. The cryptography is right; the identity is not"
    state 1-ana
    step signer verify contract.txt --sig contract.txt.sig --pub ana.pub
    pause
    say "Mallory edited the contract, signed it as Ana with HER key, and sends her .pub to Bob"
    say "Bob has never seen Ana's key before"
    state 1
    step diff contract.txt mallory/contract.txt
    step signer verify mallory/contract.txt --sig mallory/contract.txt.sig --pub mallory.pub
    say "VALID. Compare the fingerprint with the one Ana gave us in person:"
    step cat ana.fingerprint
}

demo2() {
    say "Demo 2: one changed character"
    state 2
    step diff contract.txt contract_tampered.txt
    step signer verify contract_tampered.txt --sig contract.txt.sig --pub ana.pub
}

demo3() {
    say "Demo 3: editing the signer name inside the .sig"
    state 3
    sed 's/"Ana Perez"/"Professor X"/' contract.txt.sig > forged.sig
    step grep signerName forged.sig
    step signer verify contract.txt --sig forged.sig --pub ana.pub
}

demo4() {
    say "Demo 4: brute force against the .key, 10 seconds each"
    step tools bruteforce weak.key 10
    step tools bruteforce strong.key 10
}

demo5() {
    say "Demo 5: OpenSSL verifies our signature, so it is standard RSA-PSS"
    step tools export contract.txt contract.txt.sig openssl
    step openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 \
        -verify ana.pub -signature openssl/signature.bin openssl/m.bin
}

demo6() {
    say "Demo 6: replaying an old version"
    state 6
    cp replay/v2.txt replay/contract.txt
    step signer verify replay/contract.txt --sig replay/v2.sig --pub ana.pub --previous replay/v1.sig
    pause
    say "Someone presents version 1 again, with its genuine signature"
    cp replay/v1.txt replay/contract.txt
    step signer verify replay/contract.txt --sig replay/v1.sig --pub ana.pub
    pause
    say "The limit: on a machine that never saw version 2, it is valid"
    state 6-elsewhere
    step signer verify replay/contract.txt --sig replay/v1.sig --pub ana.pub
}

demo7() {
    say "Demo 7: trust on first use, like SSH. Mallory again"
    state 7
    step signer verify contract.txt --sig contract.txt.sig --pub ana.pub
    step signer verify mallory/contract.txt --sig mallory/contract.txt.sig --pub mallory.pub
    pause
    say "Level a: the fingerprint Ana gave us in person"
    step signer verify mallory/contract.txt --sig mallory/contract.txt.sig --pub mallory.pub \
        --expect-fingerprint "$(cat ana.fingerprint)"
    pause
    say "The limit: if Mallory comes first, her key is the one pinned"
    state 7-mallory-first
    step signer verify mallory/contract.txt --sig mallory/contract.txt.sig --pub mallory.pub
    step signer verify contract.txt --sig contract.txt.sig --pub ana.pub
}

demo8() {
    say "Demo 8: a certificate authority vouches for the key"
    state 8
    step signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt
    step signer verify mallory/contract.txt --sig mallory/contract.txt.sig --cert mallory.crt --ca ca.crt
    pause
    say "Ana's laptop is stolen: the authority revokes her certificate"
    cp ca-empty.crl ca.crl
    step signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca.crl
    step signer ca revoke --ca ca --cert ana.crt
    step signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca.crl
    say "The limit: whoever does not get the new list still accepts the key"
    step signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca-empty.crl
    pause
    say "Time stamp from the time authority: the date no longer comes from Ana alone"
    step signer verify contract.txt --sig contract.txt.sig --pub ana.pub \
        --timestamp contract.txt.sig.tst --tsa-pub tsa.pub
    say "The same from the authority as a service (demo/commands.sh tsa in another terminal)"
    rm -f contract.txt.sig.live.tst
    step signer tsa request contract.txt.sig --url http://127.0.0.1:8318 --out contract.txt.sig.live.tst
    step signer verify contract.txt --sig contract.txt.sig --pub ana.pub \
        --timestamp contract.txt.sig.live.tst --tsa-pub tsa.pub
    pause
    say "Real RFC 3161 time stamp from a public authority (needs internet)"
    mkdir -p rfc3161
    step openssl ts -query -data contract.txt.sig -sha256 -cert -out rfc3161/request.tsq
    step curl -sS -H "Content-Type: application/timestamp-query" --data-binary @rfc3161/request.tsq \
        -o rfc3161/response.tsr https://freetsa.org/tsr
    curl -sS -o rfc3161/cacert.pem https://freetsa.org/files/cacert.pem
    curl -sS -o rfc3161/tsa.crt https://freetsa.org/files/tsa.crt
    step openssl ts -verify -data contract.txt.sig -in rfc3161/response.tsr \
        -CAfile rfc3161/cacert.pem -untrusted rfc3161/tsa.crt
    openssl ts -reply -in rfc3161/response.tsr -text | grep 'Time stamp:'
}

demo9() {
    say "Demo 9: what you see is not necessarily what you sign"
    state 9
    rm -f invoice.pdf.sig
    step signer sign invoice.pdf --key ana.key --signer "Ana Perez"
}

case "${1:-}" in
    setup) setup ;;
    tsa) cd "$WORK" 2> /dev/null || { echo "Run: demo/commands.sh setup"; exit 1; }; signer tsa serve --key tsa.key ;;
    [1-9]) cd "$WORK" 2> /dev/null || { echo "Run: demo/commands.sh setup"; exit 1; }; "demo$1" ;;
    all)
        cd "$WORK" 2> /dev/null || { echo "Run: demo/commands.sh setup"; exit 1; }
        for n in 1 2 3 4 5 6 7 8 9; do "demo$n"; pause; done
        ;;
    *) sed -n '2,11p' "$0"; exit 2 ;;
esac
