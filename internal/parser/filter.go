package parser

import "regexp"

var CasinoRegex = regexp.MustCompile(`(?i)[ck]a+[szc3]+[iley1]+n+[0-9o]|[vw][uy]+[l1]+[kc]a+n|[vw]a+[vw]+a+d+a|1?x-*bet|most-*bet|leon-*bet|rio-*bet|mel-*bet|ramen-*bet|marathon-*bet|max-*bet|bet-*win|gg-*bet|spin-*bet|banzai-*bet|1iks-*bet|x-*slot|sloto.*zal|max-*slot|bk-*leon|gold-*fishka|play-*fortuna|dragon.*money|poker.*dom|1-*win|crypto-*bos|free-*spin|fair-*spin|no-*deposit|igrovye|avtomaty|bookmaker|zerkalo|slottica|sykaaa|admiral-*x|x-*admiral|pinup-*bet|pari-*match|betting|partypoker|jackpot|bonus|azino[0-9-]|888-*starz|zooma[0-9-]|zenit-*bet|eldorado|slots|vodka|newretro|platinum|igrat|flagman|arkada`)

func IsCasino(domain string) bool {
	return CasinoRegex.MatchString(domain)
}
