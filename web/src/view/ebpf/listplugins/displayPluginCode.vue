<template>
  <div style="width:100%;height:500px;overflow-x:auto;overflow-y:auto;">
    <pre>
      <code>
        {{ pluginCode }}
      </code>
    </pre>
  </div>
</template>

<script setup>
defineProps({
  pluginCode: {
    type: String,
    default: ''
  },
})
</script>
<style lang="scss" scoped>

</style>
