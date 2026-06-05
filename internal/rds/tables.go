// SPDX-License-Identifier: AGPL-3.0-or-later

package rds

// g0Charset is the RDS default G0 character set (IEC 62106 Annex E),
// mapping each of the 256 code points to its UTF-8 rendering. Control
// codes and undefined positions render as a blank; 0x0A and 0x0D are
// preserved as line-feed / carriage-return (the latter is the RadioText
// terminator). Ported verbatim from the redsea reference table.
var g0Charset = [256]string{
	" ", " ", " ", " ", " ", " ", " ", " ", " ", " ", "\n", " ", " ", "\r", " ", " ",
	" ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", "\u00ad",
	" ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
	"@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
	"P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "[", "\\", "]", "―", "_",
	"‖", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
	"p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "{", "|", "}", "¯", " ",
	"á", "à", "é", "è", "í", "ì", "ó", "ò", "ú", "ù", "Ñ", "Ç", "Ş", "β", "¡", "Ĳ",
	"â", "ä", "ê", "ë", "î", "ï", "ô", "ö", "û", "ü", "ñ", "ç", "ş", "ǧ", "ı", "ĳ",
	"ª", "α", "©", "‰", "Ǧ", "ě", "ň", "ő", "π", "€", "£", "$", "←", "↑", "→", "↓",
	"º", "¹", "²", "³", "±", "İ", "ń", "ű", "µ", "¿", "÷", "°", "¼", "½", "¾", "§",
	"Á", "À", "É", "È", "Í", "Ì", "Ó", "Ò", "Ú", "Ù", "Ř", "Č", "Š", "Ž", "Ð", "Ŀ",
	"Â", "Ä", "Ê", "Ë", "Î", "Ï", "Ô", "Ö", "Û", "Ü", "ř", "č", "š", "ž", "đ", "ŀ",
	"Ã", "Å", "Æ", "Œ", "ŷ", "Ý", "Õ", "Ø", "Þ", "Ŋ", "Ŕ", "Ć", "Ś", "Ź", "Ŧ", "ð",
	"ã", "å", "æ", "œ", "ŵ", "ý", "õ", "ø", "þ", "ŋ", "ŕ", "ć", "ś", "ź", "ŧ", " ",
}

// ptyNamesRDS is the European RDS programme-type table (IEC 62106).
var ptyNamesRDS = [32]string{
	"No PTY", "News", "Current affairs", "Information",
	"Sport", "Education", "Drama", "Culture",
	"Science", "Varied", "Pop music", "Rock music",
	"Easy listening", "Light classical", "Serious classical", "Other music",
	"Weather", "Finance", "Children's programmes", "Social affairs",
	"Religion", "Phone-in", "Travel", "Leisure",
	"Jazz music", "Country music", "National music", "Oldies music",
	"Folk music", "Documentary", "Alarm test", "Alarm",
}

// ptyNamesRBDS is the North American RBDS programme-type table (NRSC-4).
var ptyNamesRBDS = [32]string{
	"No PTY", "News", "Information", "Sports",
	"Talk", "Rock", "Classic rock", "Adult hits",
	"Soft rock", "Top 40", "Country", "Oldies",
	"Soft", "Nostalgia", "Jazz", "Classical",
	"Rhythm and blues", "Soft rhythm and blues", "Language", "Religious music",
	"Religious talk", "Personality", "Public", "College",
	"Spanish talk", "Spanish music", "Hip hop", "",
	"", "Weather", "Emergency test", "Emergency",
}
