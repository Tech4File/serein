/* Serein UI primitives — first-party Web Components, no runtime package manager. */
(() => {
  const palette = ['#3c7767','#59689a','#936177','#4b7396','#8b754d','#557d72'];
  function colorFor(value = '') { let n=0; for (const ch of value) n=(n*31+ch.charCodeAt(0))>>>0; return palette[n%palette.length]; }
  if (!customElements.get('serein-avatar')) {
    customElements.define('serein-avatar', class extends HTMLElement {
      static get observedAttributes() { return ['label','size','tone']; }
      connectedCallback() { this.setAttribute('role','img'); this.render(); }
      attributeChangedCallback() { if (this.isConnected) this.render(); }
      render() {
        const label=(this.getAttribute('label')||'?').trim();
        const initials=label.split(/\s+/).filter(Boolean).slice(0,2).map(x=>x[0].toUpperCase()).join('')||'?';
        const size=this.getAttribute('size')||'md';
        const background=this.getAttribute('tone')||colorFor(label);
        this.setAttribute('aria-label',label);
        this.innerHTML='';
        const face=document.createElement('span'); face.className=`serein-avatar-face size-${size}`; face.style.setProperty('--avatar-tone',background); face.textContent=initials;
        this.append(face);
      }
    });
  }
  if (!customElements.get('serein-button')) {
    customElements.define('serein-button', class extends HTMLElement {
      static get observedAttributes() { return ['variant','disabled']; }
      connectedCallback() { if (!this.querySelector('button')) { const btn=document.createElement('button'); btn.type=this.getAttribute('type')||'button'; btn.className=`serein-button-native ${this.getAttribute('variant')||'primary'}`; btn.disabled=this.hasAttribute('disabled'); btn.append(...Array.from(this.childNodes)); this.append(btn); } }
      attributeChangedCallback() { const btn=this.querySelector('button'); if(btn){btn.disabled=this.hasAttribute('disabled');btn.className=`serein-button-native ${this.getAttribute('variant')||'primary'}`;} }
    });
  }
})();
