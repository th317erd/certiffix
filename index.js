#!/usr/bin/env node

/*
  Special thank you to Patrick Kalkman for his articles
  and resources that contributed to this effort!
*/

const Path        = require('path');
const FileSystem  = require('fs');
const Janap       = require('janap');
const Prompts     = require('prompts');
const OS          = require('os');
const Kleur       = require('kleur');
const { spawn }   = require('child_process');

const ConfigTemplate =
`
[req]
prompt = no
distinguished_name = {MASTER_NAME}

[{MASTER_NAME}]
C = {COUNTRY}
ST = {STATE}
L = {COUNTY}
O = {ORGANIZATION}
OU = {UNIT}
emailAddress = {EMAIL}
CN = {COMMONNAME}
`
;

const ConfigExtTemplate =
`
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
{DNS}
{IP}
`
;

function noe(str) {
  if (str == null)
    return true;

  if (str.replace(/\s+/g, '').length === 0)
    return true;

  return false;
}

function runCommand(command, args) {
  return new Promise((resolve) => {
    console.log(Kleur.grey(` >>> ${command} ${args.join(' ')}`));

    var childProcess = spawn(command, args);

    var stdout  = [];
    var stderr  = [];

    childProcess.stdout.on('data', (data) => {
      stdout.push(data);
    });

    childProcess.stderr.on('data', (data) => {
      stderr.push(data);
    });

    childProcess.on('error', (error) => {
      console.error(Kleur.red(`Error while running command: ${command} ${args.join(' ')}`));
      console.error(Kleur.red(error));
      process.exit(1);
    });

    childProcess.on('close', (code) => {
      if (!code)
        return resolve({ stdout, stderr, code: 0 });

      console.error(Kleur.red(`Error while running command: ${command} ${args.join(' ')}`));
      console.error(Kleur.red(stderr.join('\n')));
      process.exit(code);
    });
  });
}

function unlinkFiles(...files) {
  for (var i = 0, il = files.length; i < il; i++) {
    var fileName = files[i];
    FileSystem.unlinkSync(fileName);
  }
}

function standardMangleString(str) {
  return str.replace(/\W+/g, '_').replace(/^[^a-zA-Z]+/, '').replace(/[^a-zA-Z]+$/, '').toLowerCase();
}

function expandTemplate(template, _args) {
  var args = Object.assign({}, _args);

  if (args['organization'] == null)
    throw new Error(Kleur.red(`Required value 'organization' is missing... aborting!`));

  if (args['commonName'] == null)
    throw new Error(Kleur.red(`Required value 'commonName' is missing... aborting!`));

  args['commonname'] = args['commonName'];

  args['master_name'] = standardMangleString(`${args['organization']}:${args['commonName']}`);

  return template.replace(/\{([A-Z_]+)\}/g, (m, _key) => {
    var key   = _key.toLowerCase();
    var value = args[key];

    if (value == null)
      throw new Error(Kleur.red(`Required value '${key}' is missing... aborting!`));

    if (value instanceof Array)
      return value.map((item, index) => `${key.toUpperCase()}.${index + 1} = ${item}\n`).join('');

    return ('' + value);
  });
}

async function generateCACert(options) {
  var certName          = standardMangleString(options['dns'][0]);
  var randStr           = ('' + Math.random()).replace(/\D/g, '');
  var caConfigPath      = Path.resolve(OS.tmpdir(), `certiffix-${randStr}-ca-config.conf`);
  var caPrivateKeyPath  = Path.resolve(caPath, `${certName}.ca.key`);
  var caPublicKeyPath   = Path.resolve(caPath, `${certName}.ca.pem`);

  if (FileSystem.existsSync(caPublicKeyPath)) {
    console.error(Kleur.red(`Error: '${caPublicKeyPath}' already exists... aborting!`));
    process.exit(1);
  }

  try {
    FileSystem.writeFileSync(caConfigPath, expandTemplate(ConfigTemplate, options), 'utf8');
  } catch (error) {
    console.error(Kleur.red(`Error while attempting to write file: ${caConfigPath}: \n${error.message}`));
    process.exit(1);
  }

  await runCommand(
    'openssl',
    [
      'genpkey',
      '-algorithm',
      'RSA',
      '-out',
      caPrivateKeyPath,
      '-pkeyopt',
      'rsa_keygen_bits:4096',
    ]
  );

  await runCommand(
    'openssl',
    [
      'req',
      '-x509',
      '-new',
      '-config',
      caConfigPath,
      '-key',
      caPrivateKeyPath,
      '-sha256',
      '-days',
      '' + options['days'],
      '-out',
      caPublicKeyPath,
    ]
  );

  console.log(Kleur.green(`Success! CA Root Certificate private key written to: ${caPrivateKeyPath}`));
  console.log(Kleur.green(`Success! CA Root Certificate public key written to: ${caPublicKeyPath}`));

  console.log(Kleur.yellow(`You will need to add this CA Root Certificate to your trusted browser or system certificate authorities: ${caPublicKeyPath}`));

  unlinkFiles(
    caConfigPath,
  );
}

async function generateCert(options) {
  var caPublicKeyPath   = options['ca'];
  var caPrivateKeyPath  = options['ca'].replace(/\.ca\.pem$/, '.ca.key');

  if (!FileSystem.existsSync(caPublicKeyPath)) {
    console.error(Kleur.red(`Error: Public '${caPublicKeyPath}' CA signing certificate not found... aborting!`));
    process.exit(1);
  }

  if (!FileSystem.existsSync(caPrivateKeyPath)) {
    console.error(Kleur.red(`Error: Private '${caPrivateKeyPath}' CA signing key not found... aborting!`));
    process.exit(1);
  }

  var certName            = standardMangleString(options['dns'][0]);
  var randStr             = ('' + Math.random()).replace(/\D/g, '');
  var configPath          = Path.resolve(OS.tmpdir(), `certiffix-${randStr}-config.conf`);
  var configExtPath       = Path.resolve(OS.tmpdir(), `certiffix-${randStr}-config-ext.conf`);
  var signingRequestPath  = Path.resolve(OS.tmpdir(), `certiffix-${randStr}-csr.pem`);
  var privateKeyPath      = Path.resolve(privatePath, `${certName}.key`);
  var publicKeyPath       = Path.resolve(publicPath, `${certName}.pem`);

  try {
    FileSystem.writeFileSync(configPath, expandTemplate(ConfigTemplate, options), 'utf8');
  } catch (error) {
    console.error(Kleur.red(`Error while attempting to write file: ${configPath}: \n${error.message}`));
    process.exit(1);
  }

  try {
    FileSystem.writeFileSync(configExtPath, expandTemplate(ConfigExtTemplate, options), 'utf8');
  } catch (error) {
    console.error(Kleur.red(`Error while attempting to write file: ${configExtPath}: \n${error.message}`));
    process.exit(1);
  }

  await runCommand(
    'openssl',
    [
      'genpkey',
      '-algorithm',
      'RSA',
      '-out',
      privateKeyPath,
      '-pkeyopt',
      'rsa_keygen_bits:4096',
    ]
  );

  await runCommand(
    'openssl',
    [
      'req',
      '-new',
      '-config',
      configPath,
      '-key',
      privateKeyPath,
      '-out',
      signingRequestPath,
    ]
  );

  await runCommand(
    'openssl',
    [
      'x509',
      '-req',
      '-in',
      signingRequestPath,
      '-CA',
      caPublicKeyPath,
      '-CAkey',
      caPrivateKeyPath,
      '-CAcreateserial',
      '-out',
      publicKeyPath,
      '-days',
      '' + options['days'],
      '-extfile',
      configExtPath,
    ]
  );

  console.log(Kleur.green(`Success! Certificate private key written to: ${privateKeyPath}`));
  console.log(Kleur.green(`Success! Certificate public key written to: ${publicKeyPath}`));

  unlinkFiles(
    configPath,
    configExtPath,
    signingRequestPath,
  );
}

const configPath  = Path.resolve(OS.homedir(), '.config', 'certiffix');
const caPath      = Path.resolve(configPath, 'ca');
const privatePath = Path.resolve(configPath, 'private');
const publicPath  = Path.resolve(configPath, 'public');

try {
  FileSystem.mkdirSync(configPath,  { recursive: true, mode: 0o700 });
  FileSystem.mkdirSync(caPath,      { recursive: true, mode: 0o700 });
  FileSystem.mkdirSync(privatePath, { recursive: true, mode: 0o700 });
  FileSystem.mkdirSync(publicPath,  { recursive: true, mode: 0o700 });
} catch (error) {
  console.error(Kleur.red(`Error while attempting to create configuration directory: ${configPath}: \n${error.message}`));
}

function logHelp() {
  console.log(
(`
certiffix {options}

Generate development certificates using self-signed CA root certificates

Commands
  certiffix --ca       Generate a self-signed CA Root Certificate
  certiffix            Generate a certificate signed by the specified CA Root Certificate

Arguments
  --ca                If specified without a value, a CA Root Certificate will be generated
                      If specified with a value, then the value should be the path to a CA Root Certificate

  --commonName,       Domain name to use for certificate. If prefixed with a *., then a wildcard certificate
    --domain,         will be generated
    --cn,
    --common

  --country,          Country code value to use for the certificate
    --c

  --county,           County/Locality value to use for the certificate
    --locality,
    --l

  --days              Number of days that this certificate is valid. Default = 398

  --email             Email address value to use for the certificate

  --ip                IP Addresses to use for EXT data in certificate. Can be specified multiple times for
                      multiple IP addresses. Default = 127.0.0.1

  --organization,     Organization value to use for the certificate
    --org,
    --o

  --state,            State code value to use for the certificate
    --st

  --unit,             Unit value to use for the certificate
    --ou

  --wildcard,         If given, then the certificate will be generated as a wildcard certificate
    --wild

All arguments are optional. If not specified, the command will prompt for needed values.
`).trim());
}

var args = Janap.parse(process.argv, {
  _alias: {
    'province': 'state',
    'locality': 'county',
    'org':      'organization',
    'c':        'country',
    'st':       'state',
    'l':        'county',
    'o':        'organization',
    'ou':       'unit',
    'cn':       'commonName',
    'common':   'commonName',
    'domain':   'domain',
    'wild':     'wildcard',
  },
  _defaults: {
    days: 398,
    ip: [ '127.0.0.1' ]
  },
  ca:           String,
  commonName:   String,
  country:      String,
  county:       String,
  days:         Number,
  email:        String,
  help:         Boolean,
  ip:           [String],
  organization: String,
  state:        String,
  unit:         String,
  wildcard:     Boolean,
});

const PROMPT_QUESTIONS = [
  {
    type: 'text',
    name: 'country',
    message: 'Country',
  },
  {
    type: 'text',
    name: 'state',
    message: 'State or Province',
  },
  {
    type: 'text',
    name: 'county',
    message: 'County or Locality',
  },
  {
    type: 'text',
    name: 'organization',
    message: 'Organization',
  },
  {
    type: 'text',
    name: 'unit',
    message: 'Unit',
  },
  {
    type: 'text',
    name: 'email',
    message: 'Email',
  },
  {
    type: 'text',
    name: 'commonName',
    message: 'Common Name (domain name)',
  },
  {
    type: 'toggle',
    name: 'wildcard',
    message: 'Support Wildcard Domain?',
    initial: args.wildcard,
    active: 'yes',
    inactive: 'no'
  },
];

(async function() {
  if (args.help) {
    logHelp();
    process.exit(0);
  }

  var promptQuestions = PROMPT_QUESTIONS.filter((question) => {
    var name  = question.name;
    var value = args[name];

    if (name === 'wildcard' && ('' + args['commonName']).match(/^\*\./)) {
      args['wildcard'] = true;
      question.initial = true;
      return false;
    }

    return (value == null);
  });

  if (args.ca !== true && noe(args.ca)) {
    var choices = FileSystem.readdirSync(caPath).filter((fileName) => !!fileName.match(/\.pem$/)).map((fileName) => {
      return {
        title: fileName,
        value: Path.resolve(caPath, fileName),
      };
    });

    if (choices.length) {
      promptQuestions = [
        {
          type: 'select',
          name: 'ca',
          message: 'Choose a CA Root Certificate for signing',
          choices,
        }
      ].concat(promptQuestions);
    } else {
      console.log(Kleur.red(`Error, no CA Root Certificate available. Please generate one first with: ${process.argv[1]} --ca`));
      process.exit(1);
    }
  }

  const userResponse = (promptQuestions.length) ? await Prompts(promptQuestions, {
    onCancel: () => {
      process.exit(1);
    }
  }) : {};

  const finalArgs = Object.assign({}, args, userResponse);

  finalArgs['commonName'] = finalArgs['commonName'].replace(/^\*\./, (m) => {
    finalArgs['wildcard'] = true;
    return '';
  });

  finalArgs['dns'] = [
    finalArgs['commonName']
  ];

  if (finalArgs.wildcard)
    finalArgs['dns'] = finalArgs['dns'].concat(`*.${finalArgs['commonName']}`);

  if (finalArgs.ca === true) {
    await generateCACert(finalArgs);
  } else {
    await generateCert(finalArgs);
  }
})();
