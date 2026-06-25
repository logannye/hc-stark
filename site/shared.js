(function(){
  function ready(fn){
    if(document.readyState === 'loading'){
      document.addEventListener('DOMContentLoaded', fn);
    }else{
      fn();
    }
  }

  document.documentElement.classList.add('js');

  ready(function(){
    var mobileMedia = window.matchMedia('(max-width: 1120px)');

    document.querySelectorAll('nav.tz-nav').forEach(function(nav){
      var links = nav.querySelector('.links');
      var toggle = nav.querySelector('.hamburger');
      var currentPath = window.location.pathname.replace(/\/$/, '') || '/';

      nav.querySelectorAll('a[href]').forEach(function(anchor){
        var href = anchor.getAttribute('href');
        if(!href || href.charAt(0) !== '/') return;
        var linkPath = href.split('#')[0].split('?')[0].replace(/\/$/, '') || '/';
        if(linkPath === currentPath){
          anchor.setAttribute('aria-current', 'page');
          var group = anchor.closest('.nav-group');
          var trigger = group && group.querySelector('.nav-trigger');
          if(trigger) trigger.setAttribute('aria-current', 'page');
        }
      });

      function setNavOpen(open){
        if(links) links.classList.toggle('open', open);
        if(toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        document.body.classList.toggle('nav-open', open);
      }

      function closeMenu(){
        setNavOpen(false);
        nav.querySelectorAll('.nav-group.open').forEach(function(group){
          group.classList.remove('open');
        });
        nav.querySelectorAll('.nav-trigger[aria-expanded]').forEach(function(trigger){
          trigger.setAttribute('aria-expanded', 'false');
        });
      }

      if(toggle && links){
        toggle.addEventListener('click', function(){
          var open = !links.classList.contains('open');
          setNavOpen(open);
        });
      }

      nav.querySelectorAll('.nav-trigger').forEach(function(trigger){
        trigger.setAttribute('aria-expanded', 'false');
        trigger.addEventListener('click', function(){
          if(!mobileMedia.matches) return;
          var group = trigger.closest('.nav-group');
          if(!group) return;
          var open = !group.classList.contains('open');
          nav.querySelectorAll('.nav-group.open').forEach(function(sibling){
            if(sibling !== group) sibling.classList.remove('open');
          });
          nav.querySelectorAll('.nav-trigger[aria-expanded]').forEach(function(other){
            if(other !== trigger) other.setAttribute('aria-expanded', 'false');
          });
          group.classList.toggle('open', open);
          trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
      });

      nav.querySelectorAll('.links a').forEach(function(anchor){
        anchor.addEventListener('click', closeMenu);
      });

      document.addEventListener('keydown', function(event){
        if(event.key === 'Escape') closeMenu();
      });

      mobileMedia.addEventListener('change', function(event){
        if(!event.matches) closeMenu();
      });
    });
  });
})();
