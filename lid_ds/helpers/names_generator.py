import random

left_adjectives = ['abundant', 'acidic', 'aggressive', 'agreeable', 'alive', 'ambitious', 'ancient', 'angry', 'ashy',
                   'attractive', 'bald', 'beautiful', 'better', 'bewildered', 'big', 'billions', 'bitter', 'black',
                   'blue', 'brave', 'breezy', 'brief', 'broad', 'bumpy', 'calm', 'careful', 'chilly', 'chubby', 'clean',
                   'clever', 'clumsy', 'cold', 'colossal', 'cool', 'crashing', 'creamy', 'crooked', 'cuddly', 'curved',
                   'damaged', 'damp', 'dazzling', 'dead', 'deafening', 'deep', 'defeated', 'delicious', 'delightful',
                   'dirty', 'disgusting', 'drab', 'dry', 'eager', 'early', 'easy', 'echoing', 'elegant', 'embarrassed',
                   'enough', 'faint', 'faithful', 'famous', 'fancy', 'fast', 'fat', 'few', 'fierce', 'fit', 'flabby',
                   'flaky', 'flat', 'fluffy', 'freezing', 'fresh', 'full', 'future', 'gentle', 'gifted', 'gigantic',
                   'glamorous', 'gorgeous', 'gray', 'greasy', 'great', 'green', 'grumpy', 'hallowed', 'handsome',
                   'happy', 'harsh', 'helpful', 'helpless', 'high', 'hissing', 'hollow', 'hot', 'howling', 'huge',
                   'hundreds', 'icy', 'immense', 'important', 'incalculable', 'inexpensive', 'itchy', 'jealous',
                   'jolly', 'juicy', 'kind', 'large', 'late', 'lazy', 'lemon', 'limited', 'little', 'lively', 'long',
                   'loose', 'loud', 'low', 'magnificent', 'mammoth', 'mango', 'many', 'massive', 'mealy', 'melodic',
                   'melted', 'microscopic', 'millions', 'miniature', 'modern', 'moldy', 'most', 'muscular', 'mushy',
                   'mysterious', 'narrow', 'nervous', 'nice', 'noisy', 'numerous', 'nutritious', 'nutty', 'obedient',
                   'obnoxious', 'odd', 'old', 'old-fashioned', 'orange', 'panicky', 'petite', 'pitiful', 'plain',
                   'plump', 'polite', 'poor', 'powerful', 'prehistoric', 'prickly', 'proud', 'puny', 'purple',
                   'purring', 'putrid', 'quaint', 'quick', 'quiet', 'rancid', 'rapid', 'rapping', 'raspy', 'red',
                   'refined', 'repulsive', 'rhythmic', 'rich', 'ripe', 'rotten', 'rough', 'round', 'salmon', 'salty',
                   'savory', 'scarce', 'scary', 'scrawny', 'screeching', 'scruffy', 'shaggy', 'shallow', 'shapely',
                   'sharp', 'short', 'shrilling', 'shy', 'silly', 'skinny', 'slimy', 'slow', 'small', 'some', 'sour',
                   'sparse', 'spicy', 'spoiled', 'square', 'squeaking', 'stale', 'steep', 'sticky', 'stocky',
                   'straight', 'strong', 'substantial', 'sweet', 'swift', 'tall', 'tangy', 'tart', 'tasteless', 'tasty',
                   'teeny', 'tender', 'thankful', 'thoughtless', 'thousands', 'thundering', 'tight', 'tinkling', 'tiny',
                   'ugly', 'uneven', 'unimportant', 'uninterested', 'unkempt', 'unsightly', 'uptight', 'vast',
                   'victorious', 'wailing', 'warm', 'weak', 'wet', 'whining', 'whispering', 'white', 'wide', 'witty',
                   'wonderful', 'wooden', 'worried', 'wrong', 'yellow', 'young', 'yummy', 'zealous']

right_names = ['agnesi', 'albattani', 'allen', 'almeida', 'antonelli', 'archimedes', 'ardinghelli', 'aryabhata',
               'austin', 'babbage', 'banach', 'banzai', 'bardeen', 'bartik', 'bassi', 'beaver', 'bell', 'benz',
               'bhabha', 'bhaskara', 'black', 'blackburn', 'blackwell', 'bohr', 'booth', 'borg', 'bose', 'boyd',
               'brahmagupta', 'brattain', 'brown', 'buck', 'burnell', 'cannon', 'carson', 'cartwright', 'chandrasekhar',
               'chaplygin', 'chatelet', 'chatterjee', 'chaum', 'chebyshev', 'clarke', 'cocks', 'cohen', 'colden',
               'cori', 'cray', 'curie', 'curran', 'darwin', 'davinci', 'dewdney', 'dhawan', 'diffie', 'dijkstra',
               'dirac', 'driscoll', 'dubinsky', 'easley', 'edison', 'einstein', 'elbakyan', 'elgamal', 'elion', 'ellis',
               'engelbart', 'euclid', 'euler', 'faraday', 'feistel', 'fermat', 'fermi', 'feynman', 'franklin',
               'gagarin', 'galileo', 'galois', 'ganguly', 'gates', 'gauss', 'germain', 'goldberg', 'goldstine',
               'goldwasser', 'golick', 'goodall', 'gould', 'greider', 'grothendieck', 'haibt', 'hamilton', 'haslett',
               'hawking', 'heisenberg', 'hellman', 'hermann', 'herschel', 'hertz', 'heyrovsky', 'hodgkin', 'hofstadter',
               'hoover', 'hopper', 'hugle', 'hypatia', 'ishizaka', 'jackson', 'jang', 'jennings', 'jepsen', 'johnson',
               'joliot', 'jones', 'kalam', 'kapitsa', 'kare', 'keldysh', 'keller', 'kepler', 'khayyam', 'khorana',
               'kilby', 'kirch', 'knuth', 'kowalevski', 'lalande', 'lamarr', 'lamport', 'leakey', 'leavitt',
               'lederberg', 'lehmann', 'lewin', 'lichterman', 'liskov', 'lovelace', 'lumiere', 'mahavira', 'margulis',
               'matsumoto', 'maxwell', 'mayer', 'mccarthy', 'mcclintock', 'mclaren', 'mclean', 'mcnulty', 'meitner',
               'mendel', 'mendeleev', 'meninsky', 'merkle', 'mestorf', 'minsky', 'mirzakhani', 'montalcini', 'moore',
               'morse', 'moser', 'murdock', 'napier', 'nash', 'neumann', 'newton', 'nightingale', 'nobel', 'noether',
               'northcutt', 'noyce', 'panini', 'pare', 'pascal', 'pasteur', 'payne', 'perlman', 'pike', 'poincare',
               'poitras', 'proskuriakova', 'ptolemy', 'raman', 'ramanujan', 'rhodes', 'ride', 'ritchie', 'robinson',
               'roentgen', 'rosalind', 'rubin', 'saha', 'sammet', 'sanderson', 'shannon', 'shaw', 'shirley', 'shockley',
               'shtern', 'sinoussi', 'snyder', 'solomon', 'spence', 'stallman', 'stonebraker', 'sutherland', 'swanson',
               'swartz', 'swirles', 'taussig', 'tereshkova', 'tesla', 'tharp', 'thompson', 'torvalds', 'tu', 'turing',
               'varahamihira', 'vaughan', 'villani', 'visvesvaraya', 'volhard', 'wescoff', 'wiles', 'williams',
               'williamson', 'wilson', 'wing', 'wozniak', 'wright', 'wu', 'yalow', 'yonath', 'zhukovsky']


def scenario_name(env=None):
    mask = 0xffffffffffffffff
    seed = hash(env) & mask
    random.seed(a=seed)
    left_adjective = random.choice(left_adjectives)
    right_name = random.choice(right_names)
    return '{}_{}_{}'.format(left_adjective, right_name, str(random.randint(1000, 9999)))
