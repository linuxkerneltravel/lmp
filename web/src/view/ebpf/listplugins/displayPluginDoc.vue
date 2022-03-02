<template>
  <div>
    <iframe style="width:100%;height:500px" 
      :src="docURL" 
      scrolling="auto" 
      frameborder="0">
    </iframe>
  </div>
</template>

<script setup>
defineProps({
  docURL: {
    type: String,
    default: ''
  },
})
</script>
<style lang="scss" scoped>

</style>
