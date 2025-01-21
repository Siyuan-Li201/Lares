import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Expression, Call, ControlStructure}
import scala.collection.mutable
import scala.collection.immutable.{List, Map, Set}

// 导入 Joern 的语义 CPG 扩展库
import io.shiftleft.semanticcpg.language._

// 导入 uPickle 库用于 JSON 序列化
import upickle.default._


// 定义用于存储分析结果的数据模型
case class Statement(lineNumber: Int, code: String) {
  def toJsonMap: Map[String, Any] = Map(
    "lineNumber" -> lineNumber,
    "code" -> code
  )
}

case class ControlFlowStatements(
  dominatingStatements: List[Statement],
  firstInBlock: Option[Statement],
  firstAfterBlock: Option[Statement]
) {
  def toJsonMap: Map[String, Any] = Map(
    "dominatingStatements" -> dominatingStatements.map(_.toJsonMap),
    "firstInBlock" -> firstInBlock.map(_.toJsonMap).getOrElse(null),
    "firstAfterBlock" -> firstAfterBlock.map(_.toJsonMap).getOrElse(null)
  )
}

case class DataFlowStatements(
  definitions: List[Statement],
  uses: List[Statement]
) {
  def toJsonMap: Map[String, Any] = Map(
    "definitions" -> definitions.map(_.toJsonMap),
    "uses" -> uses.map(_.toJsonMap)
  )
}

case class AnalysisResult(
  sourceProject: String,
  functionName: String,
  targetStatement: Statement,
  controlFlowRelatedStatements: ControlFlowStatements,
  dataFlowRelatedStatements: DataFlowStatements,
  identifiers: List[String],
  constantMappings: List[String]
) {
  def toJsonMap: Map[String, Any] = Map(
    "sourceProject" -> sourceProject,
    "functionName" -> functionName,
    "targetStatement" -> targetStatement.toJsonMap,
    "controlFlowRelatedStatements" -> controlFlowRelatedStatements.toJsonMap,
    "dataFlowRelatedStatements" -> dataFlowRelatedStatements.toJsonMap,
    "identifiers" -> identifiers,
    "constantMappings" -> constantMappings
  )
}

// 实现基本的 JSON 序列化函数
def escapeString(s: String): String = {
  s.replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\b", "\\b")
    .replace("\f", "\\f")
    .replace("\n", "\\n")
    .replace("\r", "\\r")
    .replace("\t", "\\t")
}

def serializeAny(value: Any): String = value match {
  case s: String => "\"" + escapeString(s) + "\""
  case n: Number => n.toString
  case b: Boolean => b.toString
  case null => "null"
  case l: Seq[_] => listToJson(l)
  case m: Map[_, _] => mapToJson(m.asInstanceOf[Map[String, Any]])
  case Some(x) => serializeAny(x)
  case None => "null"
  case _ => "\"" + escapeString(value.toString) + "\""
}

def listToJson(list: Seq[Any]): String = {
  val items = list.map(serializeAny)
  "[\n" + items.mkString(",\n") + "\n]"
}

def mapToJson(map: Map[String, Any]): String = {
  val entries = map.map { case (key, value) =>
    val serializedValue = serializeAny(value)
    "\"" + escapeString(key) + "\": " + serializedValue
  }
  "{\n" + entries.mkString(",\n") + "\n}"
}


// 打印CFG节点的基本信息
def printCfgNodes(cfgNodes: List[nodes.CfgNode]) = {
    println("\nCFG节点信息:")
    println("总节点数: " + cfgNodes.size)
    
    cfgNodes.zipWithIndex.foreach { case (node, index) =>
        println(s"\n节点 ${index + 1}:")
        println(s"代码: ${node.code}")
        println(s"类型: ${node.label}")
        println(s"行号: ${node.lineNumber.getOrElse("未知")}")
        
        // 打印前驱节点
        val prevNodes = node.cfgPrev.l
        if (prevNodes.nonEmpty) {
            println("前驱节点:")
            prevNodes.foreach(prev => println(s"  - ${prev.code}"))
        }
        
        // 打印后继节点
        val nextNodes = node.cfgNext.l
        if (nextNodes.nonEmpty) {
            println("后继节点:")
            nextNodes.foreach(next => println(s"  - ${next.code}"))
        }
    }
}


def printMainCfgNodes(cfgNodes: List[nodes.CfgNode]) = {
    println("\n主要CFG节点信息:")
    
    // 过滤出主要节点
    val mainNodes = cfgNodes.filter(node => 
        node.label match {
            case "BLOCK" if !node.code.trim.isEmpty => true  // 非空的块
            case "CONTROL_STRUCTURE" => true  // 控制结构(if/while等)
            case "RETURN" => true    // return语句
            case "METHOD" => true    // 方法定义
            case _ => false
        }
    )
    
    println(s"主要节点数: ${mainNodes.size}")
    
    mainNodes.zipWithIndex.foreach { case (node, index) =>
        println(s"\n节点 ${index + 1}:")
        println(s"代码: ${node.code}")
        println(s"类型: ${node.label}")
        println(s"行号: ${node.lineNumber.getOrElse("未知")}")
        
        // 只显示与主要节点的连接
        val prevNodes = node.cfgPrev.l.filter(prev => mainNodes.contains(prev))
        if (prevNodes.nonEmpty) {
            println("前驱主要节点:")
            prevNodes.foreach(prev => println(s"  - ${prev.code}"))
        }
        
        val nextNodes = node.cfgNext.l.filter(next => mainNodes.contains(next))
        if (nextNodes.nonEmpty) {
            println("后继主要节点:")
            nextNodes.foreach(next => println(s"  - ${next.code}"))
        }
    }
    
    // 生成简化的DOT图
    println("\n简化的CFG图 (DOT格式):")
    println("digraph {")
    mainNodes.zipWithIndex.foreach { case (node, id) =>
        val label = node.code.replace("\"", "\\\"").replace("\n", "\\n")
        println(s"""  node${id} [label="${label}"];""")
    }
    mainNodes.zipWithIndex.foreach { case (node, id) =>
        node.cfgNext.l.filter(next => mainNodes.contains(next)).foreach { next =>
            val nextId = mainNodes.indexOf(next)
            println(s"  node${id} -> node${nextId};")
        }
    }
    println("}")
}


def printAstNodes(func: nodes.Method) = {
    println("\nAST节点信息:")
    
    def printNode(node: nodes.AstNode, depth: Int): Unit = {
        val indent = "  " * depth
        println(s"${indent}序号: ${node.order}")
        println(s"${indent}id: ${node.id}")
        println(s"${indent}行号: ${node.lineNumber}")
        println(s"${indent}列号: ${node.columnNumber}")
        println(s"${indent}类型: ${node.label}")
        println(s"${indent}代码: ${node.code}")
       // println(s"${indent}属性: ${node.properties}")
        if(node.lineNumber.isDefined) {
            println(s"${indent}行号: ${node.lineNumber.get}")
        }
    }
    
    // 递归打印AST树，明确指定返回类型为Unit
    def printAstTree(node: nodes.AstNode, depth: Int): Unit = {
        printNode(node, depth)
        // 递归打印子节点
        node.astChildren.l.foreach { child =>
            printAstTree(child, depth + 1)
        }
    }
    
    // 从方法开始打印整个AST树
    printAstTree(func, 0)
}

// 简化版本，只显示主要节点
def printMainAstNodes(func: nodes.Method) = {
    println("\n主要AST节点信息:")
    
    def isMainNode(node: nodes.AstNode): Boolean = {
        node.label match {
            case "METHOD" | "BLOCK" | "CONTROL_STRUCTURE" | "RETURN" | "LOCAL" => true
            case "CALL" if !node.code.contains("->") => true  // 只显示主要函数调用
            case _ => false
        }
    }
    
    def printNode(node: nodes.AstNode, depth: Int): Unit = {
        if (isMainNode(node)) {
            val indent = "  " * depth
            println(s"${indent}类型: ${node.label}")
            println(s"${indent}代码: ${node.code}")
            if(node.lineNumber.isDefined) {
                println(s"${indent}行号: ${node.lineNumber.get}")
            }
        }
    }
    
    def printMainAstTree(node: nodes.AstNode, depth: Int): Unit = {
        printNode(node, depth)
        node.astChildren.l.foreach { child =>
            printMainAstTree(child, depth + 1)
        }
    }
    
    printMainAstTree(func, 0)
}



// 修改后的分析函数，收集数据并返回 AnalysisResult 对象
def analyzeDominanceConstantDataflow(func: nodes.Method, targetLineNumber: Int): Option[AnalysisResult] = {
  println(s"\n分析行号 '$targetLineNumber' 的语句:")
  
  val targetStmtOption = func.ast
    .filter { node => 
      node.lineNumber.isDefined &&
      node.lineNumber.get == targetLineNumber &&
      !node.isBlock &&
      !node.isMethod
    }
    .l
    .headOption

  targetStmtOption.map { stmt =>
    println(s"目标语句: ${stmt.code}")
    
    // 根据是否是控制结构语句选择不同的处理方式
    val identifiersAndConstants = if (stmt.isControlStructure && !stmt.code.contains("goto")) {
      // 对于控制结构语句，获取第一个子节点
      val firstChild = stmt.astChildren.l.headOption
      firstChild match {
        case Some(child) => child.ast
          .filter(node => 
            node.isIdentifier || 
            node.isLiteral || 
            (node.isCall && node.code.matches("[A-Z][A-Z0-9_]*"))
          )
          .l
        case None => List()
      }
    } else {
      // 对于普通语句，直接获取当前语句的标识符
      stmt.ast
        .filter(node => 
          node.isIdentifier || 
          node.isLiteral || 
          (node.isCall && node.code.matches("[A-Z][A-Z0-9_]*"))
        )
        .l
    }

    // 收集标识符（包括变量和宏定义）
    val identifiers = identifiersAndConstants
      .filter(node => 
        node.isIdentifier || 
        (node.isCall && node.code.matches("[A-Z][A-Z0-9_]*"))
      )
      .map(_.code)
      .distinct

    println("\n标识符:")
    identifiers.foreach(println)

    // 收集宏定义和常量的映射关系
    val constantMappings = identifiersAndConstants
      .filter(node => 
        node.isCall && 
        node.code.matches("[A-Z][A-Z0-9_]*") &&
        node.ast.isLiteral.l.nonEmpty
      )
      .map(node => {
        val value = node.ast.isLiteral.l.head.code
        s"${node.code}=${value}"
      })
      .distinct

    println("\n常量映射:")
    constantMappings.foreach(println)
    
    // 数据流依赖分析
    // 1. 找出目标语句使用的变量
    val usedVars = stmt.ast.isIdentifier
      .filter(id => 
        !id.code.matches("[A-Z][A-Z0-9_]*") && // 排除宏定义
        id.lineNumber.isDefined && 
        id.lineNumber.get == stmt.lineNumber.get // 只检查同一行
      )
      .l
      .map(_.code)
      .distinct

    // 2. 找出目标语句定义的变量
    val definedVars = stmt.ast.isIdentifier
      .filter(id => 
        !id.code.matches("[A-Z][A-Z0-9_]*") && // 排除宏定义
        id.lineNumber.isDefined &&
        id.lineNumber.get == stmt.lineNumber.get && // 只检查同一行
        id.astParent.exists(_.code.contains("=")) // 检查父节点是否包含赋值
      )
      .l
      .map(_.code)
      .distinct

    // 3. 找出数据流依赖
    val dataFlowDeps = func.ast
      .filter { node =>
        !node.isBlock && 
        !node.isMethod &&
        node.lineNumber.isDefined &&
        stmt.lineNumber.isDefined &&
        ((usedVars.exists(v => node.code.contains(s"$v =")) && // 定义了目标语句使用的变量
          node.lineNumber.get < stmt.lineNumber.get) ||
         (definedVars.exists(v => node.code.contains(v)) && // 使用了目标语句定义的变量
          node.lineNumber.get > stmt.lineNumber.get))
      }
      .l
      .sortBy(_.lineNumber.getOrElse(0))

    println("\n数据流依赖分析:")

    // 分别显示定义和使用
    val (defStmtsNodes, useStmtsNodes) = dataFlowDeps.partition(node => 
      node.lineNumber.get < stmt.lineNumber.get
    )

    val definitions = defStmtsNodes.map(node => Statement(
      lineNumber = node.lineNumber.getOrElse(-1),
      code = node.code.trim
    ))

    val uses = useStmtsNodes.map(node => Statement(
      lineNumber = node.lineNumber.getOrElse(-1),
      code = node.code.trim
    ))

    // 控制流分析
    def getAllAncestors(node: nodes.AstNode): List[nodes.AstNode] = {
      node._astIn.l match {
        case parent :: _ => 
          parent.asInstanceOf[nodes.AstNode] :: getAllAncestors(parent.asInstanceOf[nodes.AstNode])
        case Nil => List()
      }
    }

    val dominatingControlStmtsNodes = getAllAncestors(stmt)
      .filter(node => 
        node.isControlStructure && 
        node.lineNumber.getOrElse(0) <= stmt.lineNumber.getOrElse(0)
      )

    val dominatingStatements = dominatingControlStmtsNodes.map(node => Statement(
      lineNumber = node.lineNumber.getOrElse(-1),
      code = node.code.trim
    ))

    println("\n支配该语句的控制流语句:")
    dominatingStatements.foreach(ds => println(s"行号 ${ds.lineNumber}: ${ds.code}"))

    var firstInBlock: Option[Statement] = None
    var firstAfterBlock: Option[Statement] = None

    if (stmt.isControlStructure && !stmt.code.contains("goto")) {
      val controlStmtCode = stmt.code

      val firstBlockNode = stmt.ast
        .filter(node => 
          node.lineNumber.getOrElse(0) > stmt.lineNumber.getOrElse(0) &&
          !controlStmtCode.contains(node.code) &&
          node._astIn.l.exists(parent => parent.id == stmt.id)
        )
        .l
        .headOption

      val firstInBlockNode = firstBlockNode.flatMap(blockNode => 
        if(blockNode.isBlock) {
          blockNode.astChildren.l.headOption
        } else {
          Some(blockNode)
        }
      )

      firstInBlock = firstInBlockNode.map(node => Statement(
        lineNumber = node.lineNumber.getOrElse(-1),
        code = node.code.trim
      ))

      println("\n控制块内的第一条语句:")
      firstInBlock.foreach(fib => println(s"行号 ${fib.lineNumber}: ${fib.code}"))

      val blockEndLine = stmt.ast
        .filter(_.lineNumber.isDefined)
        .l
        .map(_.lineNumber.get)
        .maxOption
        .getOrElse(stmt.lineNumber.getOrElse(-1))

      val firstAfterBlockNode = func.ast
        .filter(node => 
          node.lineNumber .getOrElse(0) > blockEndLine &&
          !node.asInstanceOf[nodes.AstNode].code.contains("\n") &&
          !node.isBlock
        )
        .l
        .headOption

      firstAfterBlock = firstAfterBlockNode.map(node => Statement(
        lineNumber = node.lineNumber.getOrElse(-1),
        code = node.code.trim
      ))

      println("\n控制块之后的第一条语句:")
      firstAfterBlock.foreach(fab => println(s"行号 ${fab.lineNumber}: ${fab.code}"))
    }

    // 构建分析结果对象
    val sourceProject = cpg.metaData.headOption.flatMap(_.hash).getOrElse("UnknownProject")
    val functionName = func.name

    val controlFlowRelatedStatements = ControlFlowStatements(
      dominatingStatements = dominatingStatements,
      firstInBlock = firstInBlock,
      firstAfterBlock = firstAfterBlock
    )

    val dataFlowRelatedStatements = DataFlowStatements(
      definitions = definitions,
      uses = uses
    )

    val result = AnalysisResult(
      sourceProject = sourceProject,
      functionName = functionName,
      targetStatement = Statement(
        lineNumber = stmt.lineNumber.getOrElse(-1),
        code = stmt.code.trim
      ),
      controlFlowRelatedStatements = controlFlowRelatedStatements,
      dataFlowRelatedStatements = dataFlowRelatedStatements,
      identifiers = identifiers,
      constantMappings = constantMappings
    )

    result
  }
}



// 2. 主脚本

val cpgPath = <cpgPath_arg>
val functionName = <functionName_arh>
val targetLines = <targetLines_arg>
val resPath = <resPath_arg>


// 加载 CPG
importCpg(cpgPath)


// 查找函数
val funcOption = cpg.method.nameExact(functionName).headOption

if (funcOption.isEmpty) {
  println(s"未找到函数 $functionName")
} else {
  val func = funcOption.get
  
//  printAstNodes(func)  

  // 对每个目标行号进行分析
  val analysisResults = targetLines.flatMap { lineNumber =>
    analyzeDominanceConstantDataflow(func, lineNumber)
  }

  // 序列化结果为 JSON 字符串
  val analysisResultsJson = listToJson(analysisResults.map(_.toJsonMap))

  // 保存 JSON 到文件
  import java.nio.file.{Paths, Files}
  import java.nio.charset.StandardCharsets

  Files.write(Paths.get(resPath), analysisResultsJson.getBytes(StandardCharsets.UTF_8))

  println(s"\n分析结果已保存到 $resPath")
}

