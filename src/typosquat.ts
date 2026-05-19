// ─────────────────────────────────────────────────────────────────────────────
// Dependency-Confusion / Typosquat Detection
//
// Levenshtein distance ≤ 2 to a top-package in the same ecosystem, but NOT
// itself in the top-list → suspicious.
// ─────────────────────────────────────────────────────────────────────────────

// ── Top packages per ecosystem ────────────────────────────────────────────────
// Intentionally conservative lists (real, well-known packages only).

const TOP_NPM = new Set([
  'lodash','chalk','react','axios','express','moment','typescript','webpack',
  'babel-core','eslint','prettier','jest','mocha','underscore','jquery','angular',
  'vue','next','nuxt','gatsby','svelte','rollup','parcel','vite','esbuild',
  'styled-components','redux','mobx','rxjs','ramda','immutable','socket.io',
  'mongoose','sequelize','knex','pg','mysql2','redis','mongodb','commander',
  'yargs','minimist','dotenv','cross-env','nodemon','pm2','debug','winston',
  'pino','morgan','helmet','cors','cookie-parser','body-parser','multer',
  'passport','jsonwebtoken','bcrypt','uuid','dayjs','date-fns','luxon',
  'cheerio','puppeteer','playwright','selenium-webdriver','supertest','sinon',
  'chai','nock','faker','glob','rimraf','mkdirp','fs-extra','chokidar',
  'semver','node-fetch','got','axios','ky','ws','socket.io-client','mqtt',
  'sharp','jimp','canvas','three','d3','chart.js','echarts','leaflet',
  'crypto-js','bcryptjs','argon2','node-rsa','forge','ssh2','node-ssh',
  'tar','archiver','unzipper','decompress','compressing','form-data',
  'mime','mime-types','content-type','busboy','multiparty','formidable',
  'strip-ansi','ansi-styles','supports-color','color','color-convert',
  'inquirer','ora','figures','boxen','terminal-link','conf','envfile',
  'yaml','toml','ini','js-yaml','tomlify-j0.4','dotenv-expand',
  'tslib','reflect-metadata','class-validator','class-transformer','joi',
  'zod','yup','ajv','jsonschema','tv4',
]);

const TOP_PYPI = new Set([
  'requests','numpy','pandas','scipy','matplotlib','django','flask','fastapi',
  'sqlalchemy','celery','redis','pymongo','psycopg2','boto3','botocore',
  'pillow','scikit-learn','tensorflow','torch','keras','opencv-python',
  'pytest','hypothesis','mock','coverage','tox','mypy','flake8','pylint',
  'black','isort','autopep8','pycodestyle','pydocstyle','bandit','safety',
  'cryptography','paramiko','fabric','ansible','pyyaml','toml','click',
  'typer','rich','loguru','structlog','python-dateutil','pytz','arrow',
  'six','attrs','pydantic','marshmallow','cerberus','voluptuous',
  'aiohttp','httpx','starlette','uvicorn','gunicorn','twisted','tornado',
  'grpcio','protobuf','avro','kafka-python','pika','kombu','dramatiq',
  'alembic','peewee','tortoise-orm','databases','asyncpg','aiomysql',
  'pymysql','cx-oracle','pyodbc','pyarrow','dask','polars','xlrd',
  'openpyxl','xlsxwriter','tabulate','termcolor','colorama','tqdm',
  'parameterized','factory-boy','freezegun','responses','httpretty',
  'moto','localstack','docker','kubernetes','opentelemetry-sdk',
  'prometheus-client','datadog','newrelic','sentry-sdk','rollbar',
  'stripe','twilio','sendgrid','slack-sdk','jira','pygments','sphinx',
  'mkdocs','docutils','jinja2','mako','chameleon','lxml','beautifulsoup4',
  'html5lib','cssselect','scrapy','selenium','playwright','pyppeteer',
  'pycurl','certifi','charset-normalizer','idna','urllib3','chardet',
  'werkzeug','itsdangerous','markupsafe','blinker','wtforms','cachetools',
  'wrapt','decorator','more-itertools','toolz','funcy','cytoolz',
  'apscheduler','schedule','rq','huey','prefect','airflow','luigi',
]);

const TOP_MAVEN = new Set([
  'spring-boot','spring-core','spring-web','spring-data-jpa','spring-security',
  'hibernate-core','log4j-core','logback-classic','slf4j-api','jackson-databind',
  'gson','guava','commons-lang3','commons-io','commons-collections',
  'commons-codec','commons-text','httpcomponents-client','okhttp','retrofit',
  'junit','junit-jupiter','mockito-core','assertj-core','testng','hamcrest',
  'lombok','mapstruct','flyway-core','liquibase-core','mybatis','jooq',
  'netty','grpc-java','protobuf-java','avro','kafka-clients','rabbitmq',
  'jedis','lettuce-core','mongodb-driver','elasticsearch','solr-core',
  'lucene-core','quartz','activemq','artemis','camel','cxf','jersey',
  'resteasy','dropwizard','vertx','micronaut','quarkus','helidon',
  'bouncy-castle','jasypt','jose4j','nimbus-jose-jwt','snakeyaml',
  'freemarker','thymeleaf','velocity','poi','pdfbox','itext',
  'byte-buddy','cglib','asm','javassist','reflections','classgraph',
  'arrow','vavr','joda-time','threeten','reactor-core','rxjava',
  'resilience4j','hystrix','zipkin','jaeger','opentelemetry','micrometer',
  'checkstyle','pmd','spotbugs','sonar','jacoco','pitest',
]);

const TOP_GOLANG = new Set([
  'github.com/gin-gonic/gin','github.com/labstack/echo',
  'github.com/gorilla/mux','github.com/gorilla/websocket',
  'github.com/go-chi/chi','github.com/fiber/go-fiber',
  'github.com/sirupsen/logrus','go.uber.org/zap','github.com/rs/zerolog',
  'github.com/spf13/viper','github.com/spf13/cobra',
  'github.com/stretchr/testify','github.com/golang/mock',
  'github.com/pkg/errors','github.com/go-errors/errors',
  'github.com/jinzhu/gorm','gorm.io/gorm','github.com/jmoiron/sqlx',
  'github.com/lib/pq','github.com/go-sql-driver/mysql',
  'github.com/go-redis/redis','github.com/gomodule/redigo',
  'go.mongodb.org/mongo-driver','github.com/olivere/elastic',
  'github.com/aws/aws-sdk-go','github.com/Azure/azure-sdk-for-go',
  'cloud.google.com/go','github.com/hashicorp/vault',
  'github.com/hashicorp/consul','github.com/hashicorp/terraform',
  'github.com/kubernetes/client-go','github.com/docker/docker',
  'github.com/prometheus/client_golang','go.opentelemetry.io/otel',
  'github.com/grpc/grpc-go','google.golang.org/grpc',
  'github.com/golang/protobuf','google.golang.org/protobuf',
  'github.com/nats-io/nats.go','github.com/segmentio/kafka-go',
  'github.com/Shopify/sarama','github.com/streadway/amqp',
  'github.com/dgrijalva/jwt-go','github.com/golang-jwt/jwt',
  'golang.org/x/crypto','golang.org/x/net','golang.org/x/sync',
  'github.com/go-playground/validator','github.com/google/uuid',
  'github.com/shopspring/decimal','github.com/go-yaml/yaml',
  'github.com/BurntSushi/toml','encoding/json',
  'github.com/tidwall/gjson','github.com/tidwall/sjson',
  'github.com/goccy/go-json','github.com/json-iterator/go',
  'github.com/valyala/fasthttp','github.com/julienschmidt/httprouter',
  'github.com/urfave/cli','github.com/alecthomas/kong',
  'github.com/robfig/cron','github.com/go-co-op/gocron',
  'github.com/fatih/color','github.com/pterm/pterm',
  'github.com/briandowns/spinner','github.com/charmbracelet/bubbletea',
]);

const TOP_RUBYGEMS = new Set([
  'rails','rack','bundler','rake','activesupport','activerecord',
  'actionpack','actionview','actionmailer','activejob','actioncable',
  'sprockets','uglifier','sass','coffee-rails','turbolinks',
  'devise','doorkeeper','pundit','cancancan','rolify','acts-as-taggable-on',
  'sidekiq','resque','delayed-job','whenever','rufus-scheduler',
  'nokogiri','mechanize','httparty','faraday','rest-client','typhoeus',
  'redis','hiredis','mongo','mongoid','pg','mysql2','sqlite3',
  'elasticsearch','searchkick','sunspot','sunspot_rails','ransack',
  'kaminari','will-paginate','pagy','friendly-id',
  'paperclip','carrierwave','shrine','active-storage',
  'rspec','rspec-rails','capybara','factory-bot','faker','vcr',
  'webmock','timecop','shoulda-matchers','database-cleaner',
  'puma','unicorn','thin','passenger',
  'sass-rails','bootstrap','font-awesome-sass','jquery-rails',
  'slim','haml','jbuilder','rabl','active-model-serializers',
  'rubocop','brakeman','bundler-audit','rack-attack','secure-headers',
  'jwt','bcrypt','openssl','omniauth','warden',
  'thor','gli','commander','optparse','highline',
  'minitest','test-unit','mocha','rr','flexmock',
  'pry','byebug','awesome-print','better-errors','meta-request',
  'money','money-rails','prawn','wicked-pdf','wkhtmltopdf-binary',
  'oj','multi-json','yajl-ruby','msgpack','protobuf',
  'sentry-ruby','rollbar','honeybadger','appsignal','newrelic_rpm',
  'stripe','braintree','paypal-sdk-rest','activemerchant',
  'mailgun-ruby','sendgrid-ruby','twilio-ruby','slack-ruby-client',
]);

// ── Levenshtein distance (iterative, O(n*m)) ──────────────────────────────────

function levenshtein(a: string, b: string): number {
  // Optimization: trivial cases
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const prev: number[] = Array.from({ length: b.length + 1 }, (_, i) => i);
  const curr: number[] = new Array(b.length + 1) as number[];

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        (curr[j - 1] as number) + 1,
        (prev[j] as number) + 1,
        (prev[j - 1] as number) + cost
      );
    }
    prev.splice(0, prev.length, ...curr);
  }
  return prev[b.length] as number;
}

// ── Confusable normalization ──────────────────────────────────────────────────
// Collapses visually similar chars to catch look-alike attacks.

const CONFUSABLE_MAP: Record<string, string> = {
  '0': 'o', 'l': '1', 'I': '1', '|': '1',
  'rn': 'm', 'vv': 'w', 'ii': 'u',
};

function normalizeConfusables(s: string): string {
  let out = s.toLowerCase();
  for (const [from, to] of Object.entries(CONFUSABLE_MAP)) {
    out = out.split(from).join(to);
  }
  return out;
}

// ── Ecosystem → top-set lookup ────────────────────────────────────────────────

function getTopSet(type: string | undefined): Set<string> {
  const t = (type ?? '').toLowerCase();
  if (t === 'npm' || t === 'javascript' || t === 'nodejs') return TOP_NPM;
  if (t === 'pypi' || t === 'python') return TOP_PYPI;
  if (t === 'maven' || t === 'java' || t === 'gradle') return TOP_MAVEN;
  if (t === 'golang' || t === 'go') return TOP_GOLANG;
  if (t === 'gem' || t === 'ruby' || t === 'rubygems') return TOP_RUBYGEMS;
  // If type is unknown, check all sets (conservative)
  return new Set([...TOP_NPM, ...TOP_PYPI, ...TOP_MAVEN, ...TOP_RUBYGEMS]);
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface TyposquatHit {
  name: string;
  suspiciousOf: string;
  distance: number;
}

/**
 * Detects likely typosquat/dependency-confusion candidates.
 * Returns entries where Levenshtein(name, topPkg) ≤ 2 but name ∉ top-list.
 */
export function detectTyposquat(
  components: Array<{ name: string; type?: string }>
): TyposquatHit[] {
  const hits: TyposquatHit[] = [];

  for (const comp of components) {
    const name = (comp.name ?? '').trim();
    if (!name || name.length < 3) continue;

    const topSet = getTopSet(comp.type);

    // Exact match = not suspicious
    if (topSet.has(name)) continue;

    const normName = normalizeConfusables(name);
    let bestDist = 3;
    let bestMatch = '';

    for (const top of topSet) {
      const normTop = normalizeConfusables(top);
      // Skip comparison if lengths differ by more than 2 (fast path)
      if (Math.abs(normName.length - normTop.length) > 2) continue;
      const d = levenshtein(normName, normTop);
      if (d < bestDist) {
        bestDist = d;
        bestMatch = top;
      }
      if (bestDist === 1) break; // can't do better
    }

    if (bestDist <= 2 && bestMatch) {
      hits.push({ name, suspiciousOf: bestMatch, distance: bestDist });
    }
  }

  // Deduplicate: keep only the closest match per name
  const seen = new Map<string, TyposquatHit>();
  for (const h of hits) {
    const existing = seen.get(h.name);
    if (!existing || h.distance < existing.distance) {
      seen.set(h.name, h);
    }
  }

  return [...seen.values()].sort((a, b) => a.distance - b.distance);
}
