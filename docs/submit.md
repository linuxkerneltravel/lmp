## 前言
此处介绍lmp项目的参与方法，希望大家能共同进步，共同完善lmp项目。

## 参与方式方式
具体提交 pr 的流程如下：
![](../static/imgs/submit.png)
## 详细步骤说明
### 1.fork 我们的站点项目到自己的仓库
站点仓库：https://github.com/linuxkerneltravel/lmp

fork 项目过程相对比较简单，在 https://github.com/linuxkerneltravel/lmp 页面右上角点击 fork 按钮即可， fork 到自己的空间。


### 2.clone 主仓库到本地
[https://github.com/linuxkerneltravel/website](https://github.com/linuxkerneltravel/lmp)

```sh
 username$ git clone https://github.com/linuxkerneltravel/lmp.git
 username$ cd lmp                                                                           
```
### 3.设置自己的仓库开发代码位提交上游关键
```sh
username$ git remote add dev https://github.com/linuxkerneltravel/lmp
```

### 4.新建分支，并且在新分支上修改提交代码
#### 4.1 代码更新

在每次新建分支之前一定要执行 git pull，使得  master 分支保持最新。
```sh
username$ git pull 
username$ git checkout -b pr_intro
Switched to a new branch 'pr_intro'
username$ 
```
#### 4.2 修改代码

#### 4.3 本地测试  
#### 4.4 本地测试通过之后做本地提交。
```sh
 username$ git add $yourfile
 username$ git commit -m "add new file" -a  
 username$ 
```

### 5.提交代码到 dev 上游仓库
这个 dev 上游就是上面设置的：git remote add dev  https://github.com/linuxkerneltravel/lmp

这种设置方式是可以把本地的修改按照 `dev` 标签提交到指定的另外一个仓库。我们一般是以主仓库作为我们工作目录，但是从主仓库的 `master` 分支创建出来的开发分支是不可以提交主仓库的，所以个人仓库就是这个分支提交的地方，提交之后在在个人仓库的分支和主仓库的 `master` 分支创建 `pr`。
```sh
username$ git push dev   
```
接下来就可以在自己的github上查看代码了
 `pr_intro` 分支就是提交的内容。

### 6.创建pr
在自己的个人仓库上面可以直接看到创建 pr 的按钮，直接创建就好了。

    创建 `pr` 之后，后面有修改直接提交到这个个人分支上就可以了，不用重复创建。

### 7.等待 reviewer 反馈和合并到主干
社区的管理员会对你提交的 pr 进行 review，review 后会提出修改点，或者 review 没有问题直接合到主干中。

另外如果提出问题，大家可以在这里讨论，并修改达成一致，并提交到这个分支上，最后再合到主干中。

## 总结
以上就是lmp项目的参与方式。希望大家多多参与，共同完善lmp。
　