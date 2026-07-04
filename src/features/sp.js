// Silent payments (BIP-352) feature — the reusable sp1… receive address and
// the tweak-indexer settings. (The SP scanning/spending machinery itself lives
// in wallet.js/silentpay.js and ships with the core wallet for now.)

import { isSilentPaymentAddress } from '../silentpay.js';
import { getNetwork, getSpIndexerConfig, setSpIndexerConfig, spIndexerPresets } from '../api.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';

export function spFeature(ctx) {
  const { h, ui, render, wallet, copyBtn } = ctx;

  function spIndexerCard() {
    if (!wallet.silentPaymentKeys || !wallet.silentPaymentKeys()) return null;
    const net = getNetwork();
    const cfg = getSpIndexerConfig(net);
    return h(
      'div',
      { class: 'card col' },
      h('h3', {}, t('spIndexerTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('spIndexerDesc')),
      h('select', { onChange: (e) => { setSpIndexerConfig({ server: e.target.value, url: cfg.url }, net); render(); } },
        spIndexerPresets(net).map((o) => h('option', { value: o.id, selected: o.id === cfg.server }, o.id === 'custom' ? o.label : o.url.replace(/^\w+:\/\//, '')))),
      cfg.server === 'custom'
        ? h('label', { class: 'field' },
            h('span', { class: 'lab' }, t('spIndexerUrl')),
            h('input', {
              type: 'text', class: 'mono-input', placeholder: 'https://your-indexer:8888',
              autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: cfg.url,
              onChange: (e) => { setSpIndexerConfig({ server: 'custom', url: e.target.value.trim() }, net); render(); },
            }),
            h('div', { class: 'small faint' }, t('spIndexerHint')))
        : null
    );
  }

  return {
    id: 'sp',
    receiveModes() {
      const spAddr = wallet.silentPaymentsAvailable && wallet.silentPaymentsAvailable() ? wallet.silentPaymentAddress() : null;
      if (!spAddr) return [];
      return [{
        id: 'sp', label: t('receiveSpTab'),
        render: (seg) => h(
          'div',
          { class: 'card col', style: 'align-items:center;gap:14px' },
          seg,
          h('div', { html: qrSvg(spAddr) }),
          h('div', { class: 'addr-box break', style: 'width:100%;font-size:12px' }, spAddr),
          copyBtn(spAddr, t('copyAddress'))
        ),
      }];
    },
    isSendDest(a) { return isSilentPaymentAddress(a); },
    settingsCards() { return [spIndexerCard()]; },
  };
}
