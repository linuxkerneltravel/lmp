<template>
  <div style="height:400px;overflow-x:auto;overflow-y:auto;">
    <pre>
        <code>
        {{ title }}
        </code>
    </pre>
  </div>
</template>
<script setup>
defineProps({
  title: {
    type: String,
    default: ''
  },
})
</script>
<style lang="scss" scoped>

</style>
