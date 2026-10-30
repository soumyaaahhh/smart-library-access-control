document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".alert").forEach((alert) => {
    setTimeout(() => {
      if (window.bootstrap) bootstrap.Alert.getOrCreateInstance(alert).close();
    }, 5000);
  });
});

// Attach optional browser geolocation to resource access requests. No background tracking.
document.querySelectorAll('a[href*="/resource/"], a[href*="/resource-file/"]').forEach(link=>{link.addEventListener('click',event=>{if(!navigator.geolocation || link.dataset.locationChecked==='1')return;event.preventDefault();link.dataset.locationChecked='1';const target=link.href;navigator.geolocation.getCurrentPosition(pos=>{const u=new URL(target);u.searchParams.set('lat',pos.coords.latitude);u.searchParams.set('lon',pos.coords.longitude);window.location.href=u.toString();},()=>{window.location.href=target;},{enableHighAccuracy:false,timeout:5000});});});
