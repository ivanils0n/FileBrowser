<template>
  <div class="t-container">
    <span>{{ message }}</span>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  message: string;
}>();
</script>

<style scoped>
.t-container {
  width: 100%;
  padding: 5px 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.action {
  text-align: center;
  height: 40px;
  padding: 0 10px;
  margin-left: 20px;
  border-radius: 5px;
  color: white;
  cursor: pointer;
  border: thin solid currentColor;
}

html[dir="rtl"] .action {
  margin-left: initial;
  margin-right: 20px;
}
</style>
