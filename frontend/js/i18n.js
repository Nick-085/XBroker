/**
 * XBroker Internationalization (i18n) Module
 * Provides language switching and translation capabilities
 */

class I18n {
  constructor() {
    this.currentLanguage = localStorage.getItem('language') || 'en';
    this.translations = {};
    this.supportedLanguages = {
      'en': 'English',
      'es': 'Español',
      'fr': 'Français',
      'de': 'Deutsch',
      'pt': 'Português',
      'ja': '日本語',
      'zh': '中文'
    };
  }

  /**
   * Load translations from JSON file
   */
  async loadTranslations() {
    try {
      const response = await fetch('js/translations.json');
      if (!response.ok) {
        throw new Error('Failed to load translations');
      }
      this.translations = await response.json();
    } catch (error) {
      console.error('Error loading translations:', error);
      // Fallback to empty object if translations can't be loaded
      this.translations = {};
    }
  }

  /**
   * Get translation string
   * @param {string} key - Translation key (e.g., 'login.username')
   * @param {object} params - Optional parameters for string interpolation
   * @returns {string} - Translated string or key if not found
   */
  t(key, params = {}) {
    const keys = key.split('.');
    let value = this.translations[this.currentLanguage];

    // Navigate through nested keys
    for (const k of keys) {
      if (value && typeof value === 'object') {
        value = value[k];
      } else {
        return key; // Return key if translation not found
      }
    }

    if (typeof value !== 'string') {
      return key;
    }

    // Replace parameters in string
    let result = value;
    for (const [paramKey, paramValue] of Object.entries(params)) {
      result = result.replace(new RegExp(`{{${paramKey}}}`, 'g'), paramValue);
    }

    return result;
  }

  /**
   * Get current language
   */
  getCurrentLanguage() {
    return this.currentLanguage;
  }

  /**
   * Get current language name
   */
  getCurrentLanguageName() {
    return this.supportedLanguages[this.currentLanguage] || this.currentLanguage;
  }

  /**
   * Set language and update UI
   */
  setLanguage(languageCode) {
    if (!this.supportedLanguages[languageCode]) {
      console.warn(`Language ${languageCode} not supported`);
      return false;
    }

    this.currentLanguage = languageCode;
    localStorage.setItem('language', languageCode);

    // Update HTML lang attribute
    document.documentElement.lang = languageCode;

    // Dispatch event for UI update
    window.dispatchEvent(new CustomEvent('languageChanged', { detail: languageCode }));

    return true;
  }

  /**
   * Get list of supported languages
   */
  getSupportedLanguages() {
    return this.supportedLanguages;
  }

  /**
   * Get translation for entire object
   * Useful for getting multiple related translations
   */
  getSection(section) {
    const value = this.translations[this.currentLanguage];
    if (value && typeof value === 'object') {
      return value[section] || {};
    }
    return {};
  }

  /**
   * Translate element by ID
   * Element should have data-i18n attribute with translation key
   */
  translateElement(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const key = element.dataset.i18n;
    if (!key) return;

    if (element.tagName === 'INPUT' && element.type === 'text') {
      element.placeholder = this.t(key);
    } else if (element.tagName === 'INPUT' && element.type === 'password') {
      element.placeholder = this.t(key);
    } else {
      element.textContent = this.t(key);
    }
  }

  /**
   * Translate all elements with data-i18n attribute
   */
  translatePage() {
    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(element => {
      const key = element.dataset.i18n;
      if (!key) return;

      const translation = this.t(key);

      if (element.tagName === 'INPUT') {
        if (element.type === 'text' || element.type === 'password') {
          element.placeholder = translation;
        } else {
          element.value = translation;
        }
      } else if (element.tagName === 'BUTTON' || element.tagName === 'A') {
        element.textContent = translation;
      } else {
        element.textContent = translation;
      }
    });

    // Dispatch event after translation
    window.dispatchEvent(new CustomEvent('pageTranslated', { detail: this.currentLanguage }));
  }

  /**
   * Format date based on current language
   */
  formatDate(date, format = 'short') {
    const options = format === 'long' 
      ? { year: 'numeric', month: 'long', day: 'numeric' }
      : { year: 'numeric', month: '2-digit', day: '2-digit' };

    return new Intl.DateTimeFormat(this.currentLanguage, options).format(new Date(date));
  }

  /**
   * Format number based on current language
   */
  formatNumber(number) {
    return new Intl.NumberFormat(this.currentLanguage).format(number);
  }

  /**
   * Format currency based on current language
   */
  formatCurrency(number, currency = 'USD') {
    return new Intl.NumberFormat(this.currentLanguage, {
      style: 'currency',
      currency: currency
    }).format(number);
  }
}

// Create global i18n instance
const i18n = new I18n();

// Auto-load translations when script loads
i18n.loadTranslations().then(() => {
  // Apply initial translations if DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      i18n.translatePage();
    });
  } else {
    i18n.translatePage();
  }
});
