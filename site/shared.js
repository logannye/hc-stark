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
    var mobileMedia = window.matchMedia('(max-width: 900px)');

    document.querySelectorAll('nav.tz-nav').forEach(function(nav){
      var links = nav.querySelector('.links');
      var toggle = nav.querySelector('.hamburger');

      function closeMenu(){
        if(links) links.classList.remove('open');
        if(toggle) toggle.setAttribute('aria-expanded', 'false');
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
          links.classList.toggle('open', open);
          toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
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
    });
  });
})();
