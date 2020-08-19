(async function() {
    function getVerifier(proofs, proofUrl, fingerprint) {
        for (const proof of proofs) {
            // check if the proof URI matches one of our known definitions
            const matches = proofUrl.match(new RegExp(proof.matcher));
            if (!matches) continue;

            // get all variables that were matched from the URI
            const bound = Object.entries(proof.variables)
                .map(([key, value]) => [key, matches[value || 0]])
                .reduce((previous, current) => {
                    previous[current[0]] = current[1];
                    return previous;
                }, { FINGERPRINT: fingerprint });

            // replacer function that will substitute variables in text
            const replace = text => text.replace(/\{([A-Z]+)\}/g, (_, name) => bound[name]);

            // return description of what we matched including extracted data
            return {
                profile: [proof.profile, replace(proof.profile)],
                proofUrl,
                proofJson: [proof.proof, replace(proof.proof)],
                username: [proof.username, replace(proof.username)],
                service: proof.service,
                checks: (proof.checks || []).map(check => ({
                    relation: check.relation,
                    proof: check.proof,
                    claim: check.claim.replace(/\{([A-Z]+)\}/g, (_, name) => bound[name])
                })),
                matcher: proof.matcher,
                variables: Object.entries(proof.variables).map(entry => (entry[2] = matches[entry[1]], entry))
            };
        }
        // no match
        return null;
    }

    const query = decodeURIComponent(location.href.split(/[=/]/).pop());
    const type = query.indexOf('@') == -1 ? 'fingerprint' : 'email';
    const keyUrl = `/vks/v1/by-${type}/${query}`;
    const response = await fetch(keyUrl);
    const armor = await response.text();
    const key = (await openpgp.key.readArmored(armor)).keys[0];

    // add fingerprint header
    const fingerprint = key.primaryKey.getFingerprint();

    const fprLink = document.querySelector('.fpr');
    fprLink.href = keyUrl;
    fprLink.firstElementChild.textContent = fingerprint;

    // verify primary user to use in the profile name
    const primaryUser = await key.getPrimaryUser();

    if (!await primaryUser.user.verify(key.primaryKey)) {
        throw new Error('Primary user is not valid.');
    }

    document.title = primaryUser.user.userId.name + ' — ' + document.title;
    const name = primaryUser.user.userId.name;
    document.querySelector('.name').textContent = name;

    // grab avatar from MD5 of primary user's e-mail address
    const util = openpgp.util;
    const email = primaryUser.user.userId.email;
    const digest = await openpgp.crypto.hash.md5(util.str_to_Uint8Array(email));
    const profileHash = util.str_to_hex(util.Uint8Array_to_str(digest));

    document.querySelector('.avatar').src = `https://www.gravatar.com/avatar/${profileHash}?s=148&d=mm`;

    // we support reading proof URIs from these notations
    const supportedNotations = ['proof@metacode.biz', 'proof@keys.openpgp.org'];
    const proofDefinitions = (await (await fetch('/assets/proofs.json')).json()).proofs;

    // proof URLs are gathered from all UIDs and sorted by insertion order
    const proofUrls = new Set();
    const emails = new Set([email]);

    for (const user of key.users) {
        // if verification fails for the User ID still continue with others
        try {
            const valid = await user.verify(key.primaryKey);
            // validate the User ID to avoid issues like:
            // https://bitbucket.org/skskeyserver/sks-keyserver/issues/41
            if (valid) {
                // get latest self-certification
                const cert = user.selfCertifications.reduce((a, b) => a.created > b.created ? a : b);
                (cert.notations || [])
                    // filter out non-supported notations
                    .filter(notation => supportedNotations.includes(notation[0]) && typeof notation[1] === 'string')
                    // select only values (proof URIs)
                    .map(notation => notation[1])
                    .forEach(proofUrls.add.bind(proofUrls));

                // add proof links from User Attributes too
                // this won't work on Hagrid as Hagrid never exposes User Attributes currently (2020-07-09)
                // but would work on a custom page
                if (user.userAttribute && user.userAttribute.attributes[0][0] === 'e') {
                    proofUrls.add(user.userAttribute.attributes[0].substring(user.userAttribute.attributes[0].indexOf('@') + 1));
                }
                if (user.userId && user.userId.email) {
                    emails.add(user.userId.email);
                }
            }
        } catch (e) {
            console.error('User verification error:', e);
        }
    }

    // add e-mails to the UI
    function addEmail(email) {
        const li = document.createElement('li');
        const keyLink = document.createElement('a');
        keyLink.href = 'mailto:' + email;
        keyLink.textContent = email;
        keyLink.className = 'email';
        li.appendChild(keyLink);
        return li;
    }

    for (const email of emails) {
        document.querySelector('.info').appendChild(addEmail(email));
    }

    // get text to be rendered, this could be improved by using <template>s
    function translate(id) {
        return document.getElementsByClassName('text-' + id)[0].textContent;
    }

    // add proof links for all proof URIs
    [...proofUrls]
        .sort()
        // verifier parses the proof URI
        .map(proofUrl => getVerifier(proofDefinitions, proofUrl, fingerprint))
        // filter out unknown proof URIs
        .filter(Boolean)
        .map(proof => {
            const li = document.createElement('li');
            const profile = document.createElement('a');
            profile.rel = 'me noopener nofollow';
            profile.target = '_blank';
            profile.href = proof.profile[1];
            profile.textContent = proof.username[1];
            profile.className = 'service service-' + proof.service.toLowerCase();
            li.appendChild(profile);

            const proofDiv = document.createElement('div');
            proofDiv.className = 'prooflog';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = 'chx-' + Math.random();
            proofDiv.appendChild(checkbox);

            const verification = document.createElement('label');
            verification.className = 'proof';
            verification.rel = 'me noopener nofollow';
            verification.target = '_blank';
            verification.href = proof.proofUrl;
            verification.textContent = translate('proof');
            verification.htmlFor = checkbox.id;
            proofDiv.appendChild(verification);

            const verificationLog = document.getElementById('verification-log').content.cloneNode(true);
            proofDiv.appendChild(verificationLog)

            li.appendChild(proofDiv);
            return li;
        }).forEach(document.querySelector('.proofs').appendChild.bind(document.querySelector('.proofs')));

    const randomRange = (from, to) => Math.ceil(Math.random() * (to - from) + from);
    const delay = () => new Promise(resolve => setTimeout(resolve, randomRange(800, 1100)));

    async function checkProofs() {
        const proofs = document.querySelectorAll('.proof');
        proofs.forEach(async function(proofLink, key) {
            // validation inserts random delay so it's visible that the verification
            // happens in the browser
            await delay();
            console.log(key + '. Verification of: ' + proofLink.href);
            const verifier = getVerifier(proofDefinitions, proofLink.href, fingerprint);
            console.log(key + '. Verifier details:', verifier);
            const verificationLog = proofLink.parentNode.querySelector('.balloon');
            const checks = verifier.checks;
            let json;
            let error = null;
            let success = true;
            let step = 1;
            // fetching proof document using CORS mode and no referrer header
            // note that this still leaks domain name through `Origin` header
            // Accept:application/json header is required to get JSON representation
            // in some cases (like Mastodon) it is critical
            try {
                json = await (await fetch(verifier.proofJson[1], {
                    headers: {
                        Accept: 'application/json'
                    },
                    mode: 'cors',
                    referrerPolicy: 'no-referrer'
                })).json();
            } catch (e) {
                console.log(key + '. Could not download JSON proof: ', e);
                error = e;
                success = false;
            }
            let claimValue = checks[checks.length - 1].claim;
            if (!error) {
                step = 2;
                try {
                    // do proof related checks on the JSON document
                    for (const check of checks) {
                        // extract value from the proof JSON document
                        const proofValue = check.proof.reduce((previous, current) => {
                            if (current == null || previous == null) return null;
                            if (Array.isArray(previous) && typeof current === 'string') {
                                return previous.map(value => value[current]);
                            }
                            return previous[current];
                        }, json);
                        // get the value that we need to see in the JSON document
                        claimValue = check.claim;
                        if (check.relation === 'eq') {
                            // we need strict equality for this value
                            // (useful for simple fields like OpenPGP field in Mastodon)
                            if (proofValue !== claimValue) {
                                console.log(`${key}. Check failed: claimed value ${claimValue} is not equal to ${proofValue}`);
                                success = false;
                            }
                        } else if (check.relation === 'contains') {
                            // the text need to include the claimed value
                            // (useful to large fields like Description or Bio on HackerNews)
                            if (!proofValue || proofValue.indexOf(claimValue) === -1) {
                                console.log(`${key}. Check failed: claimed value ${claimValue} is not present in ${proofValue}`);
                                success = false;
                            }
                        } else if (check.relation === 'oneOf') {
                            // claimed value must be one of the values in the resulting array
                            // useful when we have multiple fields (like DNS TXT records)
                            if (!proofValue || proofValue.indexOf(claimValue) === -1) {
                                console.log(`${key}. Check failed: claimed value ${claimValue} is not included in ${proofValue}`);
                                success = false;
                            }
                        }
                        if (!success){
                            throw new Error('Verification failed.');
                        }
                    }
                    proofLink.textContent = translate('verified');
                    proofLink.classList.add('verified');
                } catch (e) {
                    console.error(key + '. Could not verify proof: ', e);
                    error = e;
                    success = false;
                }
            }
            console.log(key + '. ' + (success ? 'Success' : 'Failure'));
            // renders verification log based on verification results
            const model = {
                proofUrl: verifier.proofUrl,
                verificationText: claimValue,
                username: verifier.username[1],
                service: verifier.service,
                error: error ? error.message : null,
                step,
                success
            };
            bindModel(verificationLog, model);
        });
    }

    checkProofs();

    function bindModel(root, model) {
        for (const elem of root.querySelectorAll('[data-bind]')) {
            for (const [modelKey, elemKey] of elem.dataset.bind.split(' ').map(pair => pair.split(':'))) {
                elem[elemKey] = model[modelKey];
            }
        }
    }

    document.addEventListener('click', e => {
        let element = e.target;
        // close the ballon if someone clicked "close" button or outside of the ballon
        while (element) {
            if (element.classList.contains('close')) {
                break;
            }
            if (element.classList.contains('balloon') || 'checked' in element) {
                return;
            }
            element = element.parentElement;
        }
        Array.from(document.querySelectorAll('input[type="checkbox"]'), checkbox => checkbox.checked = false);
    });

}());
