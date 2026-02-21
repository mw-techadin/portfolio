/* ─────────────────────────────────────────────────────────────
   Portfolio Main JS
   ───────────────────────────────────────────────────────────── */

// ── Navbar scroll state ──────────────────────────────────────
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => {
  if (window.scrollY > 60) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
}, { passive: true });

// ── Mobile menu toggle ───────────────────────────────────────
const menuBtn    = document.getElementById('menu-btn');
const mobileMenu = document.getElementById('mobile-menu');
const menuIcon   = document.getElementById('menu-icon');

menuBtn.addEventListener('click', () => {
  const open = !mobileMenu.classList.contains('hidden');
  mobileMenu.classList.toggle('hidden', open);
  menuIcon.setAttribute('d', open
    ? 'M4 6h16M4 12h16M4 18h16'          // hamburger
    : 'M6 18L18 6M6 6l12 12'             // X
  );
});

// Close mobile menu on link click
document.querySelectorAll('.mobile-nav-link').forEach(link => {
  link.addEventListener('click', () => {
    mobileMenu.classList.add('hidden');
    menuIcon.setAttribute('d', 'M4 6h16M4 12h16M4 18h16');
  });
});

// ── Scroll-reveal (Intersection Observer) ────────────────────
const revealEls = document.querySelectorAll('.reveal');
const observer  = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

revealEls.forEach(el => observer.observe(el));

// ── Active nav highlight on scroll ───────────────────────────
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-link');

const sectionObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === '#' + entry.target.id) {
          link.classList.add('active');
        }
      });
    }
  });
}, { threshold: 0.4 });

sections.forEach(section => sectionObserver.observe(section));

// ── Typewriter effect ─────────────────────────────────────────
const phrases = [
  'Security Engineer',
  'Detection Engineer',
  'DevSecOps Enthusiast',
  'Cloud Security',
  'Automation Builder',
];
let phraseIdx = 0;
let charIdx   = 0;
let deleting  = false;
const el = document.getElementById('typewriter');

function typewrite() {
  const current = phrases[phraseIdx];
  if (!deleting) {
    el.textContent = current.slice(0, charIdx + 1);
    charIdx++;
    if (charIdx === current.length) {
      deleting = true;
      setTimeout(typewrite, 1800);
      return;
    }
  } else {
    el.textContent = current.slice(0, charIdx - 1);
    charIdx--;
    if (charIdx === 0) {
      deleting  = false;
      phraseIdx = (phraseIdx + 1) % phrases.length;
    }
  }
  setTimeout(typewrite, deleting ? 50 : 90);
}

typewrite();

// ── Smooth scroll for anchor links ───────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(link => {
  link.addEventListener('click', (e) => {
    const target = document.querySelector(link.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});
