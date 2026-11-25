// Multilingual Profanity Filter (server-authoritative)
// Censors profanity from Indonesian/Malay, regional, English, Spanish, French,
// German, Portuguese, Italian, Russian, Japanese, Korean, Chinese, Arabic,
// Tagalog, Turkish, Hindi, Polish, and Dutch using Unicode & leetspeak normalization.

const EXACT_WORDS = new Set([
  // Indonesian & Malay & Javanese/Sundanese
  'anjing', 'anjir', 'anjrit', 'anjay', 'anying', 'asu', 'bangsat', 'bajingan',
  'babi', 'bacot', 'bego', 'bebal', 'bencong', 'banci', 'brengsek', 'brengsex',
  'cibai', 'cok', 'coeg', 'cuk', 'cukimai', 'dancok', 'dancuk', 'entot', 'ewe',
  'gathel', 'gatel', 'goblok', 'goblog', 'idiot', 'jancok', 'jancuk', 'jangkrik',
  'jembut', 'kampret', 'kampang', 'keparat', 'kerek', 'kimak', 'kontol', 'kntl',
  'koplok', 'kunyuk', 'lonte', 'matamu', 'memek', 'mmk', 'monyet', 'ndasmu',
  'ngentot', 'ngtd', 'ngewe', 'pantek', 'peler', 'pepek', 'perek', 'pukimak',
  'raimu', 'sialan', 'setan', 'sinting', 'sompret', 'sundal', 'taek', 'tai',
  'tahi', 'tetek', 'toket', 'tolol', 'udik', 'colmek', 'coli', 'bokep',
  'pelacur', 'jalang', 'bejad', 'biadab', 'bedebah', 'modar', 'mampus',
  'bangke', 'bangkai', 'sarap', 'pecun', 'jablay', 'bloon', 'dungu', 'laknat',
  'titit', 'burit', 'dubur', 'kehed', 'belegug', 'bedes', 'kirik',
  // English
  'fuck', 'fucker', 'fucking', 'fucked', 'fck', 'fuk', 'motherfucker', 'mf',
  'shit', 'shitty', 'bullshit', 'bitch', 'bitches', 'bastard', 'asshole',
  'arsehole', 'dick', 'dickhead', 'cock', 'cunt', 'pussy', 'whore', 'slut',
  'hoe', 'wanker', 'twat', 'prick', 'bollocks', 'bugger', 'crap', 'douche',
  'douchebag', 'faggot', 'fag', 'nigger', 'nigga', 'retard', 'retarded',
  'porn', 'hentai', 'blowjob', 'handjob', 'jackass', 'dumbass', 'dipshit',
  'shithead', 'stfu', 'gtfo', 'wtf', 'kys', 'cum', 'jizz', 'dildo', 'boobs',
  'tits', 'milf', 'thot', 'skank', 'scumbag', 'rape', 'rapist', 'ass',
  // Spanish
  'puta', 'puto', 'pendejo', 'cabron', 'mierda', 'chinga', 'chingar', 'chingada',
  'pinche', 'verga', 'culero', 'maricon', 'joder', 'cono', 'gilipollas',
  'capullo', 'hijodeputa', 'malparido', 'gonorrea', 'boludo', 'pelotudo',
  'carajo', 'mamada', 'zorra', 'perra',
  // French
  'merde', 'putain', 'salope', 'connard', 'connasse', 'encule', 'enculer',
  'foutre', 'bordel', 'batard', 'petasse', 'nique', 'ntm', 'fdp', 'filsdepute',
  'couille', 'bite', 'chatte', 'cul', 'abruti', 'crevard',
  // German
  'scheisse', 'arschloch', 'hurensohn', 'fotze', 'wichser', 'schlampe', 'ficken',
  'fick', 'miststuck', 'drecksau', 'spast', 'vollidiot', 'verdammt', 'kacke',
  'schwanz', 'nutte',
  // Portuguese
  'porra', 'caralho', 'buceta', 'foder', 'foda', 'fodase', 'filhodaputa',
  'desgraca', 'viado', 'arrombado', 'cuzao', 'babaca', 'otario', 'vagabunda',
  'cacete',
  // Italian
  'cazzo', 'vaffanculo', 'stronzo', 'puttana', 'troia', 'coglione', 'bastardo',
  'minchia', 'fanculo', 'deficiente',
  // Russian (romanized)
  'blyat', 'blyad', 'suka', 'cyka', 'khuy', 'hui', 'pizda', 'ebat', 'yebat',
  'pidor', 'pidoras', 'mudak', 'gandon', 'nahui', 'nakhui',
  // Japanese (romanized)
  'kuso', 'kusoyaro', 'chikusho', 'chinko', 'manko', 'yariman', 'kutabare',
  'fuzakeruna', 'bakayaro', 'aho',
  // Korean (romanized)
  'ssibal', 'shibal', 'sibal', 'byeongsin', 'byungsin', 'gaesaekki', 'saekki',
  'jiral', 'jonna',
  // Chinese (pinyin / initials)
  'cnm', 'tmd', 'nmsl', 'shabi', 'caonima', 'tamade', 'wocaonima', 'gundan',
  'hundan', 'biaozi',
  // Arabic (romanized)
  'kosomak', 'kuss', 'sharmouta', 'sharmuta', 'kahba', 'qahba', 'ibnelkalb',
  'khawal', 'manyouk',
  // Tagalog
  'putangina', 'tangina', 'gago', 'gagu', 'ulol', 'tarantado', 'bobo', 'tanga',
  'pakyu', 'kantot', 'pokpok', 'punyeta', 'leche', 'kupal', 'burat', 'puke',
  'tite', 'hindot',
  // Turkish / Hindi / Polish / Dutch
  'amk', 'aq', 'siktir', 'sik', 'orospu', 'pic', 'yarrak', 'anani',
  'madarchod', 'bhenchod', 'behenchod', 'chutiya', 'bhosdike', 'gandu',
  'harami', 'kamina', 'randi', 'lund', 'chut', 'kurwa', 'chuj', 'pierdol',
  'jebac', 'spierdalaj', 'kanker', 'klootzak', 'tering', 'hoer', 'lul',
]);

// Long / unambiguous roots matched inside compounds/usernames (e.g. "xXkontolXx", "superfuck99")
const SUBSTRING_ROOTS = [
  'anjing', 'bangsat', 'bajingan', 'brengsek', 'dancok', 'dancuk', 'goblok',
  'goblog', 'jancok', 'jancuk', 'jembut', 'kampret', 'keparat', 'kontol',
  'memek', 'ngentot', 'ngewe', 'pantek', 'pepek', 'pukimak', 'pelacur',
  'sundal', 'tolol', 'colmek', 'bokep', 'motherfucker', 'fucker', 'fucking',
  'fuck', 'bullshit', 'asshole', 'arsehole', 'dickhead', 'bitch', 'bastard',
  'whore', 'faggot', 'nigger', 'nigga', 'retard', 'blowjob', 'handjob',
  'dipshit', 'shithead', 'scumbag', 'pendejo', 'cabron', 'mierda', 'chingar',
  'chingada', 'hijodeputa', 'malparido', 'putangina', 'tangina', 'sharmouta',
  'sharmuta', 'kosomak', 'madarchod', 'bhenchod', 'behenchod', 'chutiya',
  'bhosdike', 'hurensohn', 'arschloch', 'scheisse', 'vaffanculo', 'stronzo',
  'puttana', 'caralho', 'buceta', 'filhodaputa', 'arrombado', 'putain',
  'salope', 'connard', 'enculer', 'filsdepute', 'blyat', 'pizda', 'pidor',
  'mudak', 'gandon', 'ssibal', 'shibal', 'byeongsin', 'gaesaekki', 'caonima',
  'wocaonima', 'shabi', 'kurwa', 'spierdalaj', 'klootzak',
].sort((a, b) => b.length - a.length);

// Exact phrases (normalized spaces)
const PHRASES = [
  'putang ina',
  'tang ina',
  'figlio di puttana',
  'testa di cazzo',
  'porco dio',
  'suck my',
];

// Non-Latin exact script tokens (Cyrillic, Japanese, Korean, Chinese, Arabic)
const NON_LATIN_PATTERNS = [
  // Russian Cyrillic
  'блядь', 'блять', 'сука', 'хуй', 'пизда', 'ебать', 'ёбаный', 'ебаный',
  'пидор', 'пидорас', 'мудак', 'гандон', 'дерьмо', 'уёбок', 'уебок',
  'залупа', 'шлюха',
  // Japanese
  'くそ', 'クソ', '糞', '死ね', 'しね', 'シネ', '馬鹿', 'ばか', 'バカ',
  'アホ', 'あほ', 'ちんこ', 'チンコ', 'まんこ', 'マンコ', 'ファック',
  'ビッチ', 'くたばれ', 'きもい', 'ざけんな', 'ふざけんな', 'ちくしょう',
  // Korean
  '씨발', '시발', 'ㅅㅂ', 'ㅆㅂ', '병신', 'ㅂㅅ', '개새끼', '새끼', '지랄',
  'ㅈㄹ', '미친놈', '미친년', '존나', '좆', '보지', '자지', '창녀',
  '꺼져', '닥쳐', '썅', '호로',
  // Chinese
  '操你妈', '草泥马', '妈的', '他妈的', '傻逼', '傻b', '煞笔', '牛逼',
  '滚蛋', '混蛋', '王八蛋', '去死', '尼玛', '婊子', '贱人', '畜生', '狗娘养的',
  // Arabic
  'كسمك', 'شرموطة', 'شرموط', 'قحبة', 'قحبه', 'زبي', 'طيز', 'ابن الكلب',
  'يلعن', 'عاهرة', 'منيك', 'خول',
];

const SAFE_ALLOWLIST = new Set([
  'classic', 'assassin', 'night', 'malam', 'lampor', 'desa', 'obor', 'keris',
  'hello', 'pass', 'class', 'grass', 'skill', 'title', 'shell', 'bass',
  'glass', 'mass', 'compass', 'embassy', 'harass', 'scunthorpe', 'cockpit',
  'peacock', 'dickens', 'hancock', 'scrap', 'scrape', 'scraping',
]);

function stripDiacritics(s) {
  return s
    .replace(/ß/g, 'ss')
    .replace(/ø/g, 'o')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '');
}

function normalizeLeet(s) {
  return stripDiacritics(s.toLowerCase())
    .replace(/0/g, 'o')
    .replace(/[1!|]/g, 'i')
    .replace(/3/g, 'e')
    .replace(/[4@]/g, 'a')
    .replace(/[5$]/g, 's')
    .replace(/[7+]/g, 't')
    .replace(/8/g, 'b');
}

function collapseRuns(s, maxRun = 1) {
  let out = '';
  let prev = '';
  let count = 0;
  for (const ch of s) {
    if (ch === prev) {
      count += 1;
      if (count <= maxRun) out += ch;
    } else {
      prev = ch;
      count = 1;
      out += ch;
    }
  }
  return out;
}

function isTokenProfane(rawToken) {
  if (!rawToken) return false;
  const lowRaw = stripDiacritics(rawToken.toLowerCase());
  if (SAFE_ALLOWLIST.has(lowRaw)) return false;

  const leet = normalizeLeet(rawToken);
  const alphaOnlyRaw = lowRaw.replace(/[^a-z]/g, '');
  if (SAFE_ALLOWLIST.has(alphaOnlyRaw)) return false;

  const candidates = new Set([
    lowRaw,
    alphaOnlyRaw,
    collapseRuns(lowRaw, 1),
    collapseRuns(lowRaw, 2),
    leet,
    collapseRuns(leet, 1),
    collapseRuns(leet, 2),
    leet.replace(/[^a-z]/g, ''),
    collapseRuns(leet.replace(/[^a-z]/g, ''), 1),
    collapseRuns(leet.replace(/[^a-z]/g, ''), 2),
  ]);

  // Split underscores inside usernames (e.g. "x_fuck_1")
  for (const seg of rawToken.split(/[_\-.]+/)) {
    if (seg && seg.length >= 2) {
      const segLow = stripDiacritics(seg.toLowerCase());
      const segLeet = normalizeLeet(seg);
      candidates.add(segLow);
      candidates.add(collapseRuns(segLow, 1));
      candidates.add(collapseRuns(segLow, 2));
      candidates.add(segLeet);
      candidates.add(collapseRuns(segLeet, 1));
      candidates.add(collapseRuns(segLeet, 2));
    }
  }

  for (const cand of candidates) {
    if (!cand) continue;
    if (EXACT_WORDS.has(cand)) {
      return true;
    }
  }

  // Substring check against unambiguous long roots (and masked like f*ck -> check stripped non-letters when token had mask chars)
  const hadMaskSymbol = /[*@#$!._-]/.test(rawToken);
  for (const cand of candidates) {
    if (!cand || cand.length < 4) continue;
    for (const root of SUBSTRING_ROOTS) {
      if (cand.includes(root)) {
        // Avoid triggering inside safe English words ending/containing substrings when not masked
        if (!hadMaskSymbol && root === 'fuck' && cand.includes('fuchs')) continue;
        return true;
      }
    }
  }

  // Also check explicit masked short variants like "f*ck", "s*it", "c*k", "b*tch"
  if (hadMaskSymbol) {
    const strippedWildcard = rawToken.toLowerCase().replace(/[*_\-.]/g, '');
    if (EXACT_WORDS.has(strippedWildcard)) return true;
  }

  return false;
}

export function censorProfanity(input) {
  if (input === null || input === undefined) return '';
  let text = String(input);
  if (!text) return '';

  // 1. Replace Non-Latin profanities directly (case-insensitive)
  for (const pat of NON_LATIN_PATTERNS) {
    if (!pat) continue;
    if (text.toLowerCase().includes(pat.toLowerCase())) {
      const escaped = pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      text = text.replace(new RegExp(escaped, 'gi'), '***');
    }
  }

  // 2. Replace multi-word Latin phrases
  for (const phrase of PHRASES) {
    const parts = phrase.split(' ').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const re = new RegExp(`\\b${parts.join('[\\s._*\\-]+')}\\b`, 'gi');
    text = text.replace(re, '***');
  }

  // 3. Replace obfuscated separated-letter sequences like "f.u.c.k", "a n j i n g", "k-o-n-t-o-l"
  text = text.replace(/\b(?:[a-zA-Z0-9@$!*](?:[\s.*_-]+)){2,}[a-zA-Z0-9@$!*]\b/g, (match) => {
    const compact = normalizeLeet(match).replace(/[^a-z]/g, '');
    const collapsed = collapseRuns(compact, 1);
    if (
      EXACT_WORDS.has(compact) ||
      EXACT_WORDS.has(collapsed) ||
      SUBSTRING_ROOTS.some((r) => compact.includes(r) || collapsed.includes(r))
    ) {
      return '***';
    }
    return match;
  });

  // 4. Token-by-token scan preserving punctuation/whitespace
  text = text.replace(/[A-Za-z0-9_\u00C0-\u024F*@!$+|]+/g, (rawMatch) => {
    // Preserve trailing sentence punctuation like '!' (e.g., "anjing!", "b4ngs4t!")
    let trailing = '';
    let token = rawMatch;
    while (token.length > 1 && (token.endsWith('!') || token.endsWith('+'))) {
      trailing = token.slice(-1) + trailing;
      token = token.slice(0, -1);
    }
    // Handle direct * wildcard patterns like "f*ck", "b*tch", "k*nt*l"
    if (token.includes('*')) {
      const stripped = token.toLowerCase().replace(/\*/g, '');
      const starCount = (token.match(/\*/g) || []).length;
      if (starCount < token.length) {
        for (const w of EXACT_WORDS) {
          if (w.length === token.length && stripped.length >= 2) {
            let matched = true;
            for (let i = 0; i < token.length; i += 1) {
              const tc = token[i].toLowerCase();
              if (tc !== '*' && tc !== w[i] && normalizeLeet(tc) !== w[i]) {
                matched = false;
                break;
              }
            }
            if (matched) return '***' + trailing;
          }
        }
      }
    }
    if (isTokenProfane(token)) {
      return '***' + trailing;
    }
    return rawMatch;
  });

  // Collapse adjacent duplicate "***" separated only by punctuation or nothing
  text = text.replace(/(\*\*\*){2,}/g, '***');
  return text;
}

export function containsProfanity(input) {
  if (input === null || input === undefined) return false;
  const s = String(input);
  if (!s.trim()) return false;
  return censorProfanity(s) !== s;
}
