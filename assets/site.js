/* Keep native, keyboard-accessible navigation visible at desktop widths. */
(() => {
  const menu = document.querySelector('.site-menu');
  if (!menu) return;
  const desktop = window.matchMedia('(min-width: 1140px)');
  const toggle = menu.querySelector('summary');
  const adaptMenu = () => { menu.open = desktop.matches; };
  adaptMenu();
  desktop.addEventListener('change', adaptMenu);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !desktop.matches && menu.open) {
      menu.open = false;
      toggle.focus();
    }
  });
  document.addEventListener('click', event => {
    if (!desktop.matches && menu.open && !menu.contains(event.target)) {
      menu.open = false;
    }
  });
  menu.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      if (!desktop.matches) menu.open = false;
    });
  });
})();
