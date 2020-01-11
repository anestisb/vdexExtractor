#!/usr/bin/env bash

# Ensure script is sourced
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

# compact_dex_converter dependencies URLs as compiled from AOSP matching API levels
readonly L_DEPS_URL_API_28='https://onedrive.live.com/download?cid=D1FAC8CC6BE2C2B0&resid=D1FAC8CC6BE2C2B0%21581&authkey=AE_kzPqzG_-R4T0'
readonly D_DEPS_URL_API_28='https://onedrive.live.com/download?cid=D1FAC8CC6BE2C2B0&resid=D1FAC8CC6BE2C2B0%21580&authkey=ADMmFqIo6bj7X5Y'
readonly L_DEPS_URL_API_29='https://onedrive.live.com/download?cid=D1FAC8CC6BE2C2B0&resid=D1FAC8CC6BE2C2B0%21603&authkey=AA1Uig7ufSzi6Sw'

readonly L_DEPS_API_28_SIG='fa722f44dea926fbe019c2fa520cc7d5e3cf9dd0cd59ff32d7189e8102977118'
readonly D_DEPS_API_28_SIG='f3b5005a608d4ce12234f4cce307ecd74c9f88dde57e2af4c4df1c29a79de196'
readonly L_DEPS_API_29_SIG='64a2103254c97377f356daa7432023ef823b42ae090e2ad577b83991cb4005e2'
